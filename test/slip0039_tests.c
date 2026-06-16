/**
 * Copyright (c) 2026 edtubbs
 * Copyright (c) 2026 The Dogecoin Foundation
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

#include <test/utest.h>

#include <dogecoin/mem.h>
#include <dogecoin/slip0039.h>
#include <dogecoin/utils.h>

#include <stdint.h>
#include <string.h>

/* Simple sanity check that a string contains only [a-z ] characters and at
 * least one space, i.e. looks like a SLIP-0039 mnemonic phrase. */
static int looks_like_mnemonic(const char* s)
{
    int spaces = 0;
    if (!s || !*s) return 0;
    for (const char* p = s; *p; ++p) {
        if (*p == ' ') { ++spaces; continue; }
        if (*p < 'a' || *p > 'z') return 0;
    }
    return spaces >= 19; /* min 20 words for a 128-bit secret = 19 spaces */
}

/* Trezor reference test vectors for SLIP-0039.
 * Source: https://github.com/trezor/python-shamir-mnemonic/blob/master/vectors.json
 */
static void test_trezor_vectors(void)
{
    uint8_t secret[64];
    size_t  slen;
    int     rc;

    /* Vector 1: 1. Valid mnemonic without sharing (128 bits) */
    static const char v1_s1[] = "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision keyboard";
    { const char* sh[] = { v1_s1 };
    slen = sizeof(secret); rc = dogecoin_slip0039_recover_secret(sh, 1, (const uint8_t*)"TREZOR", 6, secret, &slen);
    static const uint8_t e1[16] = { 0xbb, 0x54, 0xaa, 0xc4, 0xb8, 0x9d, 0xc8, 0x68, 0xba, 0x37, 0xd9, 0xcc, 0x21, 0xb2, 0xce, 0xce };
    u_assert_int_eq(rc, 0); u_assert_int_eq((int)slen, 16); u_assert_mem_eq(secret, e1, 16); }

    /* Vector 2: 2. Mnemonic with invalid checksum (128 bits) */
    static const char v2_s1[] = "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision kidney";
    { const char* sh[] = { v2_s1 };
    slen = sizeof(secret); rc = dogecoin_slip0039_recover_secret(sh, 1, (const uint8_t*)"TREZOR", 6, secret, &slen);
    u_assert_int_eq(rc, -1); /* expected failure */ }

    /* Vector 3: 3. Mnemonic with invalid padding (128 bits) */
    static const char v3_s1[] = "duckling enlarge academic academic email result length solution fridge kidney coal piece deal husband erode duke ajar music cargo fitness";
    { const char* sh[] = { v3_s1 };
    slen = sizeof(secret); rc = dogecoin_slip0039_recover_secret(sh, 1, (const uint8_t*)"TREZOR", 6, secret, &slen);
    u_assert_int_eq(rc, -1); /* expected failure */ }

    /* Vector 4: 4. Basic sharing 2-of-3 (128 bits) */
    static const char v4_s1[] = "shadow pistol academic always adequate wildlife fancy gross oasis cylinder mustang wrist rescue view short owner flip making coding armed";
    static const char v4_s2[] = "shadow pistol academic acid actress prayer class unknown daughter sweater depict flip twice unkind craft early superior advocate guest smoking";
    { const char* sh[] = { v4_s1, v4_s2 };
    slen = sizeof(secret); rc = dogecoin_slip0039_recover_secret(sh, 2, (const uint8_t*)"TREZOR", 6, secret, &slen);
    static const uint8_t e4[16] = { 0xb4, 0x3c, 0xeb, 0x7e, 0x57, 0xa0, 0xea, 0x87, 0x66, 0x22, 0x16, 0x24, 0xd0, 0x1b, 0x08, 0x64 };
    u_assert_int_eq(rc, 0); u_assert_int_eq((int)slen, 16); u_assert_mem_eq(secret, e4, 16); }

    /* Vector 5: 5. Basic sharing 2-of-3 (128 bits) */
    static const char v5_s1[] = "shadow pistol academic always adequate wildlife fancy gross oasis cylinder mustang wrist rescue view short owner flip making coding armed";
    { const char* sh[] = { v5_s1 };
    slen = sizeof(secret); rc = dogecoin_slip0039_recover_secret(sh, 1, (const uint8_t*)"TREZOR", 6, secret, &slen);
    u_assert_int_eq(rc, -1); /* expected failure */ }

    /* Vector 6: 6. Mnemonics with different identifiers (128 bits) */
    static const char v6_s1[] = "adequate smoking academic acid debut wine petition glen cluster slow rhyme slow simple epidemic rumor junk tracks treat olympic tolerate";
    static const char v6_s2[] = "adequate stay academic agency agency formal party ting frequent learn upstairs remember smear leaf damage anatomy ladle market hush corner";
    { const char* sh[] = { v6_s1, v6_s2 };
    slen = sizeof(secret); rc = dogecoin_slip0039_recover_secret(sh, 2, (const uint8_t*)"TREZOR", 6, secret, &slen);
    u_assert_int_eq(rc, -1); /* expected failure */ }

    /* Vector 7: 7. Mnemonics with different iteration exponents (128 bits) */
    static const char v7_s1[] = "peasant leaves academic acid desert exact olympic math alive axle trial tackle drug deny decent smear dominant desert bucket remind";
    static const char v7_s2[] = "peasant leader academic agency cultural blessing percent network envelope medal junk primary human pumps jacket fragment payroll ticket evoke voice";
    { const char* sh[] = { v7_s1, v7_s2 };
    slen = sizeof(secret); rc = dogecoin_slip0039_recover_secret(sh, 2, (const uint8_t*)"TREZOR", 6, secret, &slen);
    u_assert_int_eq(rc, -1); /* expected failure */ }

    /* Vector 8: 8. Mnemonics with mismatching group thresholds (128 bits) */
    static const char v8_s1[] = "liberty category beard echo animal fawn temple briefing math username various wolf aviation fancy visual holy thunder yelp helpful payment";
    static const char v8_s2[] = "liberty category beard email beyond should fancy romp founder easel pink holy hairy romp loyalty material victim owner toxic custody";
    static const char v8_s3[] = "liberty category academic easy being hazard crush diminish oral lizard reaction cluster force dilemma deploy force club veteran expect photo";
    { const char* sh[] = { v8_s1, v8_s2, v8_s3 };
    slen = sizeof(secret); rc = dogecoin_slip0039_recover_secret(sh, 3, (const uint8_t*)"TREZOR", 6, secret, &slen);
    u_assert_int_eq(rc, -1); /* expected failure */ }

    /* Vector 9: 9. Mnemonics with mismatching group counts (128 bits) */
    static const char v9_s1[] = "average senior academic leaf broken teacher expect surface hour capture obesity desire negative dynamic dominant pistol mineral mailman iris aide";
    static const char v9_s2[] = "average senior academic agency curious pants blimp spew clothes slice script dress wrap firm shaft regular slavery negative theater roster";
    { const char* sh[] = { v9_s1, v9_s2 };
    slen = sizeof(secret); rc = dogecoin_slip0039_recover_secret(sh, 2, (const uint8_t*)"TREZOR", 6, secret, &slen);
    u_assert_int_eq(rc, -1); /* expected failure */ }

    /* Vector 10: 10. Mnemonics with greater group threshold than group counts (128 bits) */
    static const char v10_s1[] = "music husband acrobat acid artist finance center either graduate swimming object bike medical clothes station aspect spider maiden bulb welcome";
    static const char v10_s2[] = "music husband acrobat agency advance hunting bike corner density careful material civil evil tactics remind hawk discuss hobo voice rainbow";
    static const char v10_s3[] = "music husband beard academic black tricycle clock mayor estimate level photo episode exclude ecology papa source amazing salt verify divorce";
    { const char* sh[] = { v10_s1, v10_s2, v10_s3 };
    slen = sizeof(secret); rc = dogecoin_slip0039_recover_secret(sh, 3, (const uint8_t*)"TREZOR", 6, secret, &slen);
    u_assert_int_eq(rc, -1); /* expected failure */ }

    /* Vector 11: 11. Mnemonics with duplicate member indices (128 bits) */
    static const char v11_s1[] = "device stay academic always dive coal antenna adult black exceed stadium herald advance soldier busy dryer daughter evaluate minister laser";
    static const char v11_s2[] = "device stay academic always dwarf afraid robin gravity crunch adjust soul branch walnut coastal dream costume scholar mortgage mountain pumps";
    { const char* sh[] = { v11_s1, v11_s2 };
    slen = sizeof(secret); rc = dogecoin_slip0039_recover_secret(sh, 2, (const uint8_t*)"TREZOR", 6, secret, &slen);
    u_assert_int_eq(rc, -1); /* expected failure */ }

    /* Vector 12: 12. Mnemonics with mismatching member thresholds (128 bits) */
    static const char v12_s1[] = "hour painting academic academic device formal evoke guitar random modern justice filter withdraw trouble identify mailman insect general cover oven";
    static const char v12_s2[] = "hour painting academic agency artist again daisy capital beaver fiber much enjoy suitable symbolic identify photo editor romp float echo";
    { const char* sh[] = { v12_s1, v12_s2 };
    slen = sizeof(secret); rc = dogecoin_slip0039_recover_secret(sh, 2, (const uint8_t*)"TREZOR", 6, secret, &slen);
    u_assert_int_eq(rc, -1); /* expected failure */ }

    /* Vector 13: 13. Mnemonics giving an invalid digest (128 bits) */
    static const char v13_s1[] = "guilt walnut academic acid deliver remove equip listen vampire tactics nylon rhythm failure husband fatigue alive blind enemy teaspoon rebound";
    static const char v13_s2[] = "guilt walnut academic agency brave hamster hobo declare herd taste alpha slim criminal mild arcade formal romp branch pink ambition";
    { const char* sh[] = { v13_s1, v13_s2 };
    slen = sizeof(secret); rc = dogecoin_slip0039_recover_secret(sh, 2, (const uint8_t*)"TREZOR", 6, secret, &slen);
    u_assert_int_eq(rc, -1); /* expected failure */ }

    /* Vector 14: 14. Insufficient number of groups (128 bits, case 1) */
    static const char v14_s1[] = "eraser senior beard romp adorn nuclear spill corner cradle style ancient family general leader ambition exchange unusual garlic promise voice";
    { const char* sh[] = { v14_s1 };
    slen = sizeof(secret); rc = dogecoin_slip0039_recover_secret(sh, 1, (const uint8_t*)"TREZOR", 6, secret, &slen);
    u_assert_int_eq(rc, -1); /* expected failure */ }

    /* Vector 15: 15. Insufficient number of groups (128 bits, case 2) */
    static const char v15_s1[] = "eraser senior decision scared cargo theory device idea deliver modify curly include pancake both news skin realize vitamins away join";
    static const char v15_s2[] = "eraser senior decision roster beard treat identify grumpy salt index fake aviation theater cubic bike cause research dragon emphasis counter";
    { const char* sh[] = { v15_s1, v15_s2 };
    slen = sizeof(secret); rc = dogecoin_slip0039_recover_secret(sh, 2, (const uint8_t*)"TREZOR", 6, secret, &slen);
    u_assert_int_eq(rc, -1); /* expected failure */ }

    /* Vector 16: 16. Threshold number of groups, but insufficient number of members in one group (128 bits) */
    static const char v16_s1[] = "eraser senior decision shadow artist work morning estate greatest pipeline plan ting petition forget hormone flexible general goat admit surface";
    static const char v16_s2[] = "eraser senior beard romp adorn nuclear spill corner cradle style ancient family general leader ambition exchange unusual garlic promise voice";
    { const char* sh[] = { v16_s1, v16_s2 };
    slen = sizeof(secret); rc = dogecoin_slip0039_recover_secret(sh, 2, (const uint8_t*)"TREZOR", 6, secret, &slen);
    u_assert_int_eq(rc, -1); /* expected failure */ }

    /* Vector 17: 17. Threshold number of groups and members in each group (128 bits, case 1) */
    static const char v17_s1[] = "eraser senior decision roster beard treat identify grumpy salt index fake aviation theater cubic bike cause research dragon emphasis counter";
    static const char v17_s2[] = "eraser senior ceramic snake clay various huge numb argue hesitate auction category timber browser greatest hanger petition script leaf pickup";
    static const char v17_s3[] = "eraser senior ceramic shaft dynamic become junior wrist silver peasant force math alto coal amazing segment yelp velvet image paces";
    static const char v17_s4[] = "eraser senior ceramic round column hawk trust auction smug shame alive greatest sheriff living perfect corner chest sled fumes adequate";
    static const char v17_s5[] = "eraser senior decision smug corner ruin rescue cubic angel tackle skin skunk program roster trash rumor slush angel flea amazing";
    { const char* sh[] = { v17_s1, v17_s2, v17_s3, v17_s4, v17_s5 };
    slen = sizeof(secret); rc = dogecoin_slip0039_recover_secret(sh, 5, (const uint8_t*)"TREZOR", 6, secret, &slen);
    static const uint8_t e17[16] = { 0x7c, 0x33, 0x97, 0xa2, 0x92, 0xa5, 0x94, 0x16, 0x82, 0xd7, 0xa4, 0xae, 0x2d, 0x89, 0x8d, 0x11 };
    u_assert_int_eq(rc, 0); u_assert_int_eq((int)slen, 16); u_assert_mem_eq(secret, e17, 16); }

    /* Vector 18: 18. Threshold number of groups and members in each group (128 bits, case 2) */
    static const char v18_s1[] = "eraser senior decision smug corner ruin rescue cubic angel tackle skin skunk program roster trash rumor slush angel flea amazing";
    static const char v18_s2[] = "eraser senior beard romp adorn nuclear spill corner cradle style ancient family general leader ambition exchange unusual garlic promise voice";
    static const char v18_s3[] = "eraser senior decision scared cargo theory device idea deliver modify curly include pancake both news skin realize vitamins away join";
    { const char* sh[] = { v18_s1, v18_s2, v18_s3 };
    slen = sizeof(secret); rc = dogecoin_slip0039_recover_secret(sh, 3, (const uint8_t*)"TREZOR", 6, secret, &slen);
    static const uint8_t e18[16] = { 0x7c, 0x33, 0x97, 0xa2, 0x92, 0xa5, 0x94, 0x16, 0x82, 0xd7, 0xa4, 0xae, 0x2d, 0x89, 0x8d, 0x11 };
    u_assert_int_eq(rc, 0); u_assert_int_eq((int)slen, 16); u_assert_mem_eq(secret, e18, 16); }

    /* Vector 19: 19. Threshold number of groups and members in each group (128 bits, case 3) */
    static const char v19_s1[] = "eraser senior beard romp adorn nuclear spill corner cradle style ancient family general leader ambition exchange unusual garlic promise voice";
    static const char v19_s2[] = "eraser senior acrobat romp bishop medical gesture pumps secret alive ultimate quarter priest subject class dictate spew material endless market";
    { const char* sh[] = { v19_s1, v19_s2 };
    slen = sizeof(secret); rc = dogecoin_slip0039_recover_secret(sh, 2, (const uint8_t*)"TREZOR", 6, secret, &slen);
    static const uint8_t e19[16] = { 0x7c, 0x33, 0x97, 0xa2, 0x92, 0xa5, 0x94, 0x16, 0x82, 0xd7, 0xa4, 0xae, 0x2d, 0x89, 0x8d, 0x11 };
    u_assert_int_eq(rc, 0); u_assert_int_eq((int)slen, 16); u_assert_mem_eq(secret, e19, 16); }

    /* Vector 20: 20. Valid mnemonic without sharing (256 bits) */
    static const char v20_s1[] = "theory painting academic academic armed sweater year military elder discuss acne wildlife boring employer fused large satoshi bundle carbon diagnose anatomy hamster leaves tracks paces beyond phantom capital marvel lips brave detect luck";
    { const char* sh[] = { v20_s1 };
    slen = sizeof(secret); rc = dogecoin_slip0039_recover_secret(sh, 1, (const uint8_t*)"TREZOR", 6, secret, &slen);
    static const uint8_t e20[32] = { 0x98, 0x9b, 0xaf, 0x9d, 0xca, 0xad, 0x5b, 0x10, 0xca, 0x33, 0xdf, 0xd8, 0xcc, 0x75, 0xe4, 0x24, 0x77, 0x02, 0x5d, 0xce, 0x88, 0xae, 0x83, 0xe7, 0x5a, 0x23, 0x00, 0x86, 0xa0, 0xe0, 0x0e, 0x92 };
    u_assert_int_eq(rc, 0); u_assert_int_eq((int)slen, 32); u_assert_mem_eq(secret, e20, 32); }

    /* Vector 21: 21. Mnemonic with invalid checksum (256 bits) */
    static const char v21_s1[] = "theory painting academic academic armed sweater year military elder discuss acne wildlife boring employer fused large satoshi bundle carbon diagnose anatomy hamster leaves tracks paces beyond phantom capital marvel lips brave detect lunar";
    { const char* sh[] = { v21_s1 };
    slen = sizeof(secret); rc = dogecoin_slip0039_recover_secret(sh, 1, (const uint8_t*)"TREZOR", 6, secret, &slen);
    u_assert_int_eq(rc, -1); /* expected failure */ }

    /* Vector 22: 22. Mnemonic with invalid padding (256 bits) */
    static const char v22_s1[] = "theory painting academic academic campus sweater year military elder discuss acne wildlife boring employer fused large satoshi bundle carbon diagnose anatomy hamster leaves tracks paces beyond phantom capital marvel lips facility obtain sister";
    { const char* sh[] = { v22_s1 };
    slen = sizeof(secret); rc = dogecoin_slip0039_recover_secret(sh, 1, (const uint8_t*)"TREZOR", 6, secret, &slen);
    u_assert_int_eq(rc, -1); /* expected failure */ }

    /* Vector 23: 23. Basic sharing 2-of-3 (256 bits) */
    static const char v23_s1[] = "humidity disease academic always aluminum jewelry energy woman receiver strategy amuse duckling lying evidence network walnut tactics forget hairy rebound impulse brother survive clothes stadium mailman rival ocean reward venture always armed unwrap";
    static const char v23_s2[] = "humidity disease academic agency actress jacket gross physics cylinder solution fake mortgage benefit public busy prepare sharp friar change work slow purchase ruler again tricycle involve viral wireless mixture anatomy desert cargo upgrade";
    { const char* sh[] = { v23_s1, v23_s2 };
    slen = sizeof(secret); rc = dogecoin_slip0039_recover_secret(sh, 2, (const uint8_t*)"TREZOR", 6, secret, &slen);
    static const uint8_t e23[32] = { 0xc9, 0x38, 0xb3, 0x19, 0x06, 0x76, 0x87, 0xe9, 0x90, 0xe0, 0x5e, 0x0d, 0xa0, 0xec, 0xce, 0x12, 0x78, 0xf7, 0x5f, 0xf5, 0x8d, 0x98, 0x53, 0xf1, 0x9d, 0xca, 0xee, 0xd5, 0xde, 0x10, 0x4a, 0xae };
    u_assert_int_eq(rc, 0); u_assert_int_eq((int)slen, 32); u_assert_mem_eq(secret, e23, 32); }

    /* Vector 24: 24. Basic sharing 2-of-3 (256 bits) */
    static const char v24_s1[] = "humidity disease academic always aluminum jewelry energy woman receiver strategy amuse duckling lying evidence network walnut tactics forget hairy rebound impulse brother survive clothes stadium mailman rival ocean reward venture always armed unwrap";
    { const char* sh[] = { v24_s1 };
    slen = sizeof(secret); rc = dogecoin_slip0039_recover_secret(sh, 1, (const uint8_t*)"TREZOR", 6, secret, &slen);
    u_assert_int_eq(rc, -1); /* expected failure */ }

    /* Vector 25: 25. Mnemonics with different identifiers (256 bits) */
    static const char v25_s1[] = "smear husband academic acid deadline scene venture distance dive overall parking bracelet elevator justice echo burning oven chest duke nylon";
    static const char v25_s2[] = "smear isolate academic agency alpha mandate decorate burden recover guard exercise fatal force syndrome fumes thank guest drift dramatic mule";
    { const char* sh[] = { v25_s1, v25_s2 };
    slen = sizeof(secret); rc = dogecoin_slip0039_recover_secret(sh, 2, (const uint8_t*)"TREZOR", 6, secret, &slen);
    u_assert_int_eq(rc, -1); /* expected failure */ }

    /* Vector 26: 26. Mnemonics with different iteration exponents (256 bits) */
    static const char v26_s1[] = "finger trash academic acid average priority dish revenue academic hospital spirit western ocean fact calcium syndrome greatest plan losing dictate";
    static const char v26_s2[] = "finger traffic academic agency building lilac deny paces subject threaten diploma eclipse window unknown health slim piece dragon focus smirk";
    { const char* sh[] = { v26_s1, v26_s2 };
    slen = sizeof(secret); rc = dogecoin_slip0039_recover_secret(sh, 2, (const uint8_t*)"TREZOR", 6, secret, &slen);
    u_assert_int_eq(rc, -1); /* expected failure */ }

    /* Vector 27: 27. Mnemonics with mismatching group thresholds (256 bits) */
    static const char v27_s1[] = "flavor pink beard echo depart forbid retreat become frost helpful juice unwrap reunion credit math burning spine black capital lair";
    static const char v27_s2[] = "flavor pink beard email diet teaspoon freshman identify document rebound cricket prune headset loyalty smell emission skin often square rebound";
    static const char v27_s3[] = "flavor pink academic easy credit cage raisin crazy closet lobe mobile become drink human tactics valuable hand capture sympathy finger";
    { const char* sh[] = { v27_s1, v27_s2, v27_s3 };
    slen = sizeof(secret); rc = dogecoin_slip0039_recover_secret(sh, 3, (const uint8_t*)"TREZOR", 6, secret, &slen);
    u_assert_int_eq(rc, -1); /* expected failure */ }

    /* Vector 28: 28. Mnemonics with mismatching group counts (256 bits) */
    static const char v28_s1[] = "column flea academic leaf debut extra surface slow timber husky lawsuit game behavior husky swimming already paper episode tricycle scroll";
    static const char v28_s2[] = "column flea academic agency blessing garbage party software stadium verify silent umbrella therapy decorate chemical erode dramatic eclipse replace apart";
    { const char* sh[] = { v28_s1, v28_s2 };
    slen = sizeof(secret); rc = dogecoin_slip0039_recover_secret(sh, 2, (const uint8_t*)"TREZOR", 6, secret, &slen);
    u_assert_int_eq(rc, -1); /* expected failure */ }

    /* Vector 29: 29. Mnemonics with greater group threshold than group counts (256 bits) */
    static const char v29_s1[] = "smirk pink acrobat acid auction wireless impulse spine sprinkle fortune clogs elbow guest hush loyalty crush dictate tracks airport talent";
    static const char v29_s2[] = "smirk pink acrobat agency dwarf emperor ajar organize legs slice harvest plastic dynamic style mobile float bulb health coding credit";
    static const char v29_s3[] = "smirk pink beard academic alto strategy carve shame language rapids ruin smart location spray training acquire eraser endorse submit peaceful";
    { const char* sh[] = { v29_s1, v29_s2, v29_s3 };
    slen = sizeof(secret); rc = dogecoin_slip0039_recover_secret(sh, 3, (const uint8_t*)"TREZOR", 6, secret, &slen);
    u_assert_int_eq(rc, -1); /* expected failure */ }

    /* Vector 30: 30. Mnemonics with duplicate member indices (256 bits) */
    static const char v30_s1[] = "fishing recover academic always device craft trend snapshot gums skin downtown watch device sniff hour clock public maximum garlic born";
    static const char v30_s2[] = "fishing recover academic always aircraft view software cradle fangs amazing package plastic evaluate intend penalty epidemic anatomy quarter cage apart";
    { const char* sh[] = { v30_s1, v30_s2 };
    slen = sizeof(secret); rc = dogecoin_slip0039_recover_secret(sh, 2, (const uint8_t*)"TREZOR", 6, secret, &slen);
    u_assert_int_eq(rc, -1); /* expected failure */ }

    /* Vector 31: 31. Mnemonics with mismatching member thresholds (256 bits) */
    static const char v31_s1[] = "evoke garden academic academic answer wolf scandal modern warmth station devote emerald market physics surface formal amazing aquatic gesture medical";
    static const char v31_s2[] = "evoke garden academic agency deal revenue knit reunion decrease magazine flexible company goat repair alarm military facility clogs aide mandate";
    { const char* sh[] = { v31_s1, v31_s2 };
    slen = sizeof(secret); rc = dogecoin_slip0039_recover_secret(sh, 2, (const uint8_t*)"TREZOR", 6, secret, &slen);
    u_assert_int_eq(rc, -1); /* expected failure */ }

    /* Vector 32: 32. Mnemonics giving an invalid digest (256 bits) */
    static const char v32_s1[] = "river deal academic acid average forbid pistol peanut custody bike class aunt hairy merit valid flexible learn ajar very easel";
    static const char v32_s2[] = "river deal academic agency camera amuse lungs numb isolate display smear piece traffic worthy year patrol crush fact fancy emission";
    { const char* sh[] = { v32_s1, v32_s2 };
    slen = sizeof(secret); rc = dogecoin_slip0039_recover_secret(sh, 2, (const uint8_t*)"TREZOR", 6, secret, &slen);
    u_assert_int_eq(rc, -1); /* expected failure */ }

    /* Vector 33: 33. Insufficient number of groups (256 bits, case 1) */
    static const char v33_s1[] = "wildlife deal beard romp alcohol space mild usual clothes union nuclear testify course research heat listen task location thank hospital slice smell failure fawn helpful priest ambition average recover lecture process dough stadium";
    { const char* sh[] = { v33_s1 };
    slen = sizeof(secret); rc = dogecoin_slip0039_recover_secret(sh, 1, (const uint8_t*)"TREZOR", 6, secret, &slen);
    u_assert_int_eq(rc, -1); /* expected failure */ }

    /* Vector 34: 34. Insufficient number of groups (256 bits, case 2) */
    static const char v34_s1[] = "wildlife deal decision scared acne fatal snake paces obtain election dryer dominant romp tactics railroad marvel trust helpful flip peanut theory theater photo luck install entrance taxi step oven network dictate intimate listen";
    static const char v34_s2[] = "wildlife deal decision smug ancestor genuine move huge cubic strategy smell game costume extend swimming false desire fake traffic vegan senior twice timber submit leader payroll fraction apart exact forward pulse tidy install";
    { const char* sh[] = { v34_s1, v34_s2 };
    slen = sizeof(secret); rc = dogecoin_slip0039_recover_secret(sh, 2, (const uint8_t*)"TREZOR", 6, secret, &slen);
    u_assert_int_eq(rc, -1); /* expected failure */ }

    /* Vector 35: 35. Threshold number of groups, but insufficient number of members in one group (256 bits) */
    static const char v35_s1[] = "wildlife deal decision shadow analysis adjust bulb skunk muscle mandate obesity total guitar coal gravity carve slim jacket ruin rebuild ancestor numerous hour mortgage require herd maiden public ceiling pecan pickup shadow club";
    static const char v35_s2[] = "wildlife deal beard romp alcohol space mild usual clothes union nuclear testify course research heat listen task location thank hospital slice smell failure fawn helpful priest ambition average recover lecture process dough stadium";
    { const char* sh[] = { v35_s1, v35_s2 };
    slen = sizeof(secret); rc = dogecoin_slip0039_recover_secret(sh, 2, (const uint8_t*)"TREZOR", 6, secret, &slen);
    u_assert_int_eq(rc, -1); /* expected failure */ }

    /* Vector 36: 36. Threshold number of groups and members in each group (256 bits, case 1) */
    static const char v36_s1[] = "wildlife deal ceramic round aluminum pitch goat racism employer miracle percent math decision episode dramatic editor lily prospect program scene rebuild display sympathy have single mustang junction relate often chemical society wits estate";
    static const char v36_s2[] = "wildlife deal decision scared acne fatal snake paces obtain election dryer dominant romp tactics railroad marvel trust helpful flip peanut theory theater photo luck install entrance taxi step oven network dictate intimate listen";
    static const char v36_s3[] = "wildlife deal ceramic scatter argue equip vampire together ruin reject literary rival distance aquatic agency teammate rebound false argue miracle stay again blessing peaceful unknown cover beard acid island language debris industry idle";
    static const char v36_s4[] = "wildlife deal ceramic snake agree voter main lecture axis kitchen physics arcade velvet spine idea scroll promise platform firm sharp patrol divorce ancestor fantasy forbid goat ajar believe swimming cowboy symbolic plastic spelling";
    static const char v36_s5[] = "wildlife deal decision shadow analysis adjust bulb skunk muscle mandate obesity total guitar coal gravity carve slim jacket ruin rebuild ancestor numerous hour mortgage require herd maiden public ceiling pecan pickup shadow club";
    { const char* sh[] = { v36_s1, v36_s2, v36_s3, v36_s4, v36_s5 };
    slen = sizeof(secret); rc = dogecoin_slip0039_recover_secret(sh, 5, (const uint8_t*)"TREZOR", 6, secret, &slen);
    static const uint8_t e36[32] = { 0x53, 0x85, 0x57, 0x7c, 0x8c, 0xfc, 0x6c, 0x1a, 0x8a, 0xa0, 0xf7, 0xf1, 0x0e, 0xcd, 0xe0, 0xa3, 0x31, 0x84, 0x93, 0x26, 0x25, 0x91, 0xe7, 0x8b, 0x8c, 0x14, 0xc6, 0x68, 0x61, 0x67, 0x12, 0x3b };
    u_assert_int_eq(rc, 0); u_assert_int_eq((int)slen, 32); u_assert_mem_eq(secret, e36, 32); }

    /* Vector 37: 37. Threshold number of groups and members in each group (256 bits, case 2) */
    static const char v37_s1[] = "wildlife deal decision scared acne fatal snake paces obtain election dryer dominant romp tactics railroad marvel trust helpful flip peanut theory theater photo luck install entrance taxi step oven network dictate intimate listen";
    static const char v37_s2[] = "wildlife deal beard romp alcohol space mild usual clothes union nuclear testify course research heat listen task location thank hospital slice smell failure fawn helpful priest ambition average recover lecture process dough stadium";
    static const char v37_s3[] = "wildlife deal decision smug ancestor genuine move huge cubic strategy smell game costume extend swimming false desire fake traffic vegan senior twice timber submit leader payroll fraction apart exact forward pulse tidy install";
    { const char* sh[] = { v37_s1, v37_s2, v37_s3 };
    slen = sizeof(secret); rc = dogecoin_slip0039_recover_secret(sh, 3, (const uint8_t*)"TREZOR", 6, secret, &slen);
    static const uint8_t e37[32] = { 0x53, 0x85, 0x57, 0x7c, 0x8c, 0xfc, 0x6c, 0x1a, 0x8a, 0xa0, 0xf7, 0xf1, 0x0e, 0xcd, 0xe0, 0xa3, 0x31, 0x84, 0x93, 0x26, 0x25, 0x91, 0xe7, 0x8b, 0x8c, 0x14, 0xc6, 0x68, 0x61, 0x67, 0x12, 0x3b };
    u_assert_int_eq(rc, 0); u_assert_int_eq((int)slen, 32); u_assert_mem_eq(secret, e37, 32); }

    /* Vector 38: 38. Threshold number of groups and members in each group (256 bits, case 3) */
    static const char v38_s1[] = "wildlife deal beard romp alcohol space mild usual clothes union nuclear testify course research heat listen task location thank hospital slice smell failure fawn helpful priest ambition average recover lecture process dough stadium";
    static const char v38_s2[] = "wildlife deal acrobat romp anxiety axis starting require metric flexible geology game drove editor edge screw helpful have huge holy making pitch unknown carve holiday numb glasses survive already tenant adapt goat fangs";
    { const char* sh[] = { v38_s1, v38_s2 };
    slen = sizeof(secret); rc = dogecoin_slip0039_recover_secret(sh, 2, (const uint8_t*)"TREZOR", 6, secret, &slen);
    static const uint8_t e38[32] = { 0x53, 0x85, 0x57, 0x7c, 0x8c, 0xfc, 0x6c, 0x1a, 0x8a, 0xa0, 0xf7, 0xf1, 0x0e, 0xcd, 0xe0, 0xa3, 0x31, 0x84, 0x93, 0x26, 0x25, 0x91, 0xe7, 0x8b, 0x8c, 0x14, 0xc6, 0x68, 0x61, 0x67, 0x12, 0x3b };
    u_assert_int_eq(rc, 0); u_assert_int_eq((int)slen, 32); u_assert_mem_eq(secret, e38, 32); }

    /* Vector 39: 39. Mnemonic with insufficient length */
    static const char v39_s1[] = "junk necklace academic academic acne isolate join hesitate lunar roster dough calcium chemical ladybug amount mobile glasses verify cylinder";
    { const char* sh[] = { v39_s1 };
    slen = sizeof(secret); rc = dogecoin_slip0039_recover_secret(sh, 1, (const uint8_t*)"TREZOR", 6, secret, &slen);
    u_assert_int_eq(rc, -1); /* expected failure */ }

    /* Vector 40: 40. Mnemonic with invalid master secret length */
    static const char v40_s1[] = "fraction necklace academic academic award teammate mouse regular testify coding building member verdict purchase blind camera duration email prepare spirit quarter";
    { const char* sh[] = { v40_s1 };
    slen = sizeof(secret); rc = dogecoin_slip0039_recover_secret(sh, 1, (const uint8_t*)"TREZOR", 6, secret, &slen);
    u_assert_int_eq(rc, -1); /* expected failure */ }

    /* Vector 41: 41. Valid mnemonics which can detect some errors in modular arithmetic */
    static const char v41_s1[] = "herald flea academic cage avoid space trend estate dryer hairy evoke eyebrow improve airline artwork garlic premium duration prevent oven";
    static const char v41_s2[] = "herald flea academic client blue skunk class goat luxury deny presence impulse graduate clay join blanket bulge survive dish necklace";
    static const char v41_s3[] = "herald flea academic acne advance fused brother frozen broken game ranked ajar already believe check install theory angry exercise adult";
    { const char* sh[] = { v41_s1, v41_s2, v41_s3 };
    slen = sizeof(secret); rc = dogecoin_slip0039_recover_secret(sh, 3, (const uint8_t*)"TREZOR", 6, secret, &slen);
    static const uint8_t e41[16] = { 0xad, 0x6f, 0x2a, 0xd8, 0xb5, 0x9b, 0xbb, 0xaa, 0x01, 0x36, 0x9b, 0x90, 0x06, 0x20, 0x8d, 0x9a };
    u_assert_int_eq(rc, 0); u_assert_int_eq((int)slen, 16); u_assert_mem_eq(secret, e41, 16); }

    /* Vector 42: 42. Valid extendable mnemonic without sharing (128 bits) */
    static const char v42_s1[] = "testify swimming academic academic column loyalty smear include exotic bedroom exotic wrist lobe cover grief golden smart junior estimate learn";
    { const char* sh[] = { v42_s1 };
    slen = sizeof(secret); rc = dogecoin_slip0039_recover_secret(sh, 1, (const uint8_t*)"TREZOR", 6, secret, &slen);
    static const uint8_t e42[16] = { 0x16, 0x79, 0xb4, 0x51, 0x6e, 0x0e, 0xe5, 0x95, 0x43, 0x51, 0xd2, 0x88, 0xa8, 0x38, 0xf4, 0x5e };
    u_assert_int_eq(rc, 0); u_assert_int_eq((int)slen, 16); u_assert_mem_eq(secret, e42, 16); }

    /* Vector 43: 43. Extendable basic sharing 2-of-3 (128 bits) */
    static const char v43_s1[] = "enemy favorite academic acid cowboy phrase havoc level response walnut budget painting inside trash adjust froth kitchen learn tidy punish";
    static const char v43_s2[] = "enemy favorite academic always academic sniff script carpet romp kind promise scatter center unfair training emphasis evening belong fake enforce";
    { const char* sh[] = { v43_s1, v43_s2 };
    slen = sizeof(secret); rc = dogecoin_slip0039_recover_secret(sh, 2, (const uint8_t*)"TREZOR", 6, secret, &slen);
    static const uint8_t e43[16] = { 0x48, 0xb1, 0xa4, 0xb8, 0x0b, 0x8c, 0x20, 0x9a, 0xd4, 0x2c, 0x33, 0x67, 0x2b, 0xda, 0xa4, 0x28 };
    u_assert_int_eq(rc, 0); u_assert_int_eq((int)slen, 16); u_assert_mem_eq(secret, e43, 16); }

    /* Vector 44: 44. Valid extendable mnemonic without sharing (256 bits) */
    static const char v44_s1[] = "impulse calcium academic academic alcohol sugar lyrics pajamas column facility finance tension extend space birthday rainbow swimming purple syndrome facility trial warn duration snapshot shadow hormone rhyme public spine counter easy hawk album";
    { const char* sh[] = { v44_s1 };
    slen = sizeof(secret); rc = dogecoin_slip0039_recover_secret(sh, 1, (const uint8_t*)"TREZOR", 6, secret, &slen);
    static const uint8_t e44[32] = { 0x83, 0x40, 0x61, 0x16, 0x02, 0xfe, 0x91, 0xaf, 0x63, 0x4a, 0x5f, 0x46, 0x08, 0x37, 0x7b, 0x52, 0x35, 0xfa, 0x2d, 0x75, 0x7c, 0x51, 0xd7, 0x20, 0xc0, 0xc7, 0x65, 0x62, 0x49, 0xa3, 0x03, 0x5f };
    u_assert_int_eq(rc, 0); u_assert_int_eq((int)slen, 32); u_assert_mem_eq(secret, e44, 32); }

    /* Vector 45: 45. Extendable basic sharing 2-of-3 (256 bits) */
    static const char v45_s1[] = "western apart academic always artist resident briefing sugar woman oven coding club ajar merit pecan answer prisoner artist fraction amount desktop mild false necklace muscle photo wealthy alpha category unwrap spew losing making";
    static const char v45_s2[] = "western apart academic acid answer ancient auction flip image penalty oasis beaver multiple thunder problem switch alive heat inherit superior teaspoon explain blanket pencil numb lend punish endless aunt garlic humidity kidney observe";
    { const char* sh[] = { v45_s1, v45_s2 };
    slen = sizeof(secret); rc = dogecoin_slip0039_recover_secret(sh, 2, (const uint8_t*)"TREZOR", 6, secret, &slen);
    static const uint8_t e45[32] = { 0x8d, 0xc6, 0x52, 0xd6, 0xd6, 0xcd, 0x37, 0x0d, 0x8c, 0x96, 0x31, 0x41, 0xf6, 0xd7, 0x9b, 0xa4, 0x40, 0x30, 0x0f, 0x25, 0xc4, 0x67, 0x30, 0x2c, 0x1d, 0x96, 0x6b, 0xff, 0x8f, 0x62, 0x30, 0x0d };
    u_assert_int_eq(rc, 0); u_assert_int_eq((int)slen, 32); u_assert_mem_eq(secret, e45, 32); }

}

void test_slip0039()
{
    /* Run Trezor reference test vectors first. */
    test_trezor_vectors();

    /* SLIP-0039 requires a master secret of at least 128 bits and a
     * multiple of 16 bits. Use a 16-byte fixture. */
    const uint8_t secret[16] = {
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
        0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01
    };

    SLIP0039_SHARE shares[SLIP0039_MAX_SHARES];
    dogecoin_mem_zero(shares, sizeof(shares));

    /* Generate 3-of-5 shares. */
    u_assert_int_eq(dogecoin_slip0039_generate_shares(secret, sizeof(secret), 3, 5, shares), 0);
    for (int i = 0; i < 5; ++i) {
        u_assert_int_eq(looks_like_mnemonic(shares[i]), 1);
    }
    /* Recovery from any 3 distinct shares should work. */
    const char* set_a[] = { shares[0], shares[2], shares[4] };
    uint8_t recovered[32];
    size_t recovered_len = sizeof(recovered);
    dogecoin_mem_zero(recovered, sizeof(recovered));
    u_assert_int_eq(dogecoin_slip0039_recover_secret(set_a, 3, NULL, 0, recovered, &recovered_len), 0);
    u_assert_uint64_eq(recovered_len, sizeof(secret));
    u_assert_mem_eq(recovered, secret, sizeof(secret));

    const char* set_b[] = { shares[1], shares[3], shares[4] };
    recovered_len = sizeof(recovered);
    dogecoin_mem_zero(recovered, sizeof(recovered));
    u_assert_int_eq(dogecoin_slip0039_recover_secret(set_b, 3, NULL, 0, recovered, &recovered_len), 0);
    u_assert_mem_eq(recovered, secret, sizeof(secret));

    /* Insufficient shares (below threshold) must fail. */
    const char* set_short[] = { shares[0], shares[1] };
    recovered_len = sizeof(recovered);
    u_assert_int_eq(dogecoin_slip0039_recover_secret(set_short, 2, NULL, 0, recovered, &recovered_len), -1);

    /* Duplicate share index must fail. */
    const char* set_dup[] = { shares[1], shares[1], shares[2] };
    recovered_len = sizeof(recovered);
    u_assert_int_eq(dogecoin_slip0039_recover_secret(set_dup, 3, NULL, 0, recovered, &recovered_len), -1);

    /* Tampering with any character of a mnemonic must fail RS1024 checksum
     * (or fall back to a wrong word that fails decode/digest verification). */
    char tampered[SLIP0039_MAX_SHARE_STR_SIZE];
    strncpy(tampered, shares[0], sizeof(tampered) - 1);
    tampered[sizeof(tampered) - 1] = '\0';
    /* Find the first letter and bump it within [a-z]. */
    for (size_t i = 0; tampered[i]; ++i) {
        if (tampered[i] >= 'a' && tampered[i] <= 'z') {
            tampered[i] = (tampered[i] == 'z') ? 'a' : (char)(tampered[i] + 1);
            break;
        }
    }
    const char* set_bad[] = { tampered, shares[2], shares[4] };
    recovered_len = sizeof(recovered);
    u_assert_int_eq(dogecoin_slip0039_recover_secret(set_bad, 3, NULL, 0, recovered, &recovered_len), -1);

    /* Output buffer too small must fail. */
    recovered_len = 4;
    u_assert_int_eq(dogecoin_slip0039_recover_secret(set_a, 3, NULL, 0, recovered, &recovered_len), -1);

    /* threshold = 1 (single share equals secret) round-trip works for 1-of-1. */
    SLIP0039_SHARE single[1];
    dogecoin_mem_zero(single, sizeof(single));
    u_assert_int_eq(dogecoin_slip0039_generate_shares(secret, sizeof(secret), 1, 1, single), 0);
    const char* set_one[] = { single[0] };
    recovered_len = sizeof(recovered);
    dogecoin_mem_zero(recovered, sizeof(recovered));
    u_assert_int_eq(dogecoin_slip0039_recover_secret(set_one, 1, NULL, 0, recovered, &recovered_len), 0);
    u_assert_uint64_eq(recovered_len, sizeof(secret));
    u_assert_mem_eq(recovered, secret, sizeof(secret));

    /* 32-byte (256-bit) secret round-trip with 2-of-3 shares. */
    uint8_t big_secret[32];
    for (size_t i = 0; i < sizeof(big_secret); ++i) big_secret[i] = (uint8_t)(0xA5 ^ i);
    SLIP0039_SHARE big_shares[3];
    dogecoin_mem_zero(big_shares, sizeof(big_shares));
    u_assert_int_eq(dogecoin_slip0039_generate_shares(big_secret, sizeof(big_secret), 2, 3, big_shares), 0);
    const char* big_set[] = { big_shares[0], big_shares[2] };
    uint8_t big_rec[32];
    size_t  big_len = sizeof(big_rec);
    u_assert_int_eq(dogecoin_slip0039_recover_secret(big_set, 2, NULL, 0, big_rec, &big_len), 0);
    u_assert_uint64_eq(big_len, sizeof(big_secret));
    u_assert_mem_eq(big_rec, big_secret, sizeof(big_secret));

    /* Reject secrets that are too short or odd-length. */
    SLIP0039_SHARE bad[3];
    dogecoin_mem_zero(bad, sizeof(bad));
    uint8_t short_secret[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    u_assert_int_eq(dogecoin_slip0039_generate_shares(short_secret, sizeof(short_secret), 2, 3, bad), -1);
    uint8_t odd_secret[17] = { 0 };
    u_assert_int_eq(dogecoin_slip0039_generate_shares(odd_secret, sizeof(odd_secret), 2, 3, bad), -1);
}
