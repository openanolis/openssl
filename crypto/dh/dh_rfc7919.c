/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* DH parameters from RFC7919 and RFC3526 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include "dh_local.h"
#include <openssl/bn.h>
#include <openssl/objects.h>
#include "crypto/bn_dh.h"

static DH *dh_param_init(int nid, const BIGNUM *p, const BIGNUM *q, int32_t nbits)
{
    DH *dh = DH_new();
    if (dh == NULL)
        return NULL;
    dh->p = (BIGNUM *)p;
    /*
     * We do not set q as it would enable the inefficient and
     * unnecessary pubkey modular exponentiation check.
     */
    dh->g = (BIGNUM *)&_bignum_const_2;
    dh->length = nbits;
    dh->nid = nid;
    return dh;
}

DH *DH_new_by_nid(int nid)
{
    switch (nid) {
    case NID_ffdhe2048:
        return dh_param_init(nid, &_bignum_ffdhe2048_p, &_bignum_ffdhe2048_q, 225);
    case NID_ffdhe3072:
        return dh_param_init(nid, &_bignum_ffdhe3072_p, &_bignum_ffdhe3072_q, 275);
    case NID_ffdhe4096:
        return dh_param_init(nid, &_bignum_ffdhe4096_p, &_bignum_ffdhe4096_q, 325);
    case NID_ffdhe6144:
        return dh_param_init(nid, &_bignum_ffdhe6144_p, &_bignum_ffdhe6144_q, 375);
    case NID_ffdhe8192:
        return dh_param_init(nid, &_bignum_ffdhe8192_p, &_bignum_ffdhe8192_q, 400);
    case NID_modp_2048:
        return dh_param_init(nid, &_bignum_modp_2048_p, &_bignum_modp_2048_q, 225);
    case NID_modp_3072:
        return dh_param_init(nid, &_bignum_modp_3072_p, &_bignum_modp_3072_q, 275);
    case NID_modp_4096:
        return dh_param_init(nid, &_bignum_modp_4096_p, &_bignum_modp_4096_q, 325);
    case NID_modp_6144:
        return dh_param_init(nid, &_bignum_modp_6144_p, &_bignum_modp_6144_q, 375);
    case NID_modp_8192:
        return dh_param_init(nid, &_bignum_modp_8192_p, &_bignum_modp_8192_q, 400);
    case NID_modp_1536:
        if (!FIPS_mode())
            return dh_param_init(nid, &_bignum_modp_1536_p, &_bignum_modp_1536_q, 175);
        /* fallthrough */
    default:
        DHerr(DH_F_DH_NEW_BY_NID, DH_R_INVALID_PARAMETER_NID);
        return NULL;
    }
}

static int dh_match_group(const DH *dh, BIGNUM **qout, int *lout)
{
    int nid;
    const BIGNUM *q;
    int length;

    if (BN_get_word(dh->g) != 2)
        return NID_undef;

    if (dh->nid == NID_ffdhe2048 || !BN_cmp(dh->p, &_bignum_ffdhe2048_p)) {
        nid = NID_ffdhe2048;
        q = &_bignum_ffdhe2048_q;
        length = 225;
    } else if (dh->nid == NID_ffdhe3072 || !BN_cmp(dh->p, &_bignum_ffdhe3072_p)) {
        nid = NID_ffdhe3072;
        q = &_bignum_ffdhe3072_q;
        length = 275;
    } else if (dh->nid == NID_ffdhe4096 || !BN_cmp(dh->p, &_bignum_ffdhe4096_p)) {
        nid = NID_ffdhe4096;
        q = &_bignum_ffdhe4096_q;
        length = 325;
    } else if (dh->nid == NID_ffdhe6144 || !BN_cmp(dh->p, &_bignum_ffdhe6144_p)) {
        nid = NID_ffdhe6144;
        q = &_bignum_ffdhe6144_q;
        length = 375;
    } else if (dh->nid == NID_ffdhe8192 || !BN_cmp(dh->p, &_bignum_ffdhe8192_p)) {
        nid = NID_ffdhe8192;
        q = &_bignum_ffdhe8192_q;
        length = 400;
    } else if (dh->nid == NID_modp_2048 || !BN_cmp(dh->p, &_bignum_modp_2048_p)) {
        nid = NID_modp_2048;
        q = &_bignum_modp_2048_q;
        length = 225;
    } else if (dh->nid == NID_modp_3072 || !BN_cmp(dh->p, &_bignum_modp_3072_p)) {
        nid = NID_modp_3072;
        q = &_bignum_modp_3072_q;
        length = 275;
    } else if (dh->nid == NID_modp_4096 || !BN_cmp(dh->p, &_bignum_modp_4096_p)) {
        nid = NID_modp_4096;
        q = &_bignum_modp_4096_q;
        length = 325;
    } else if (dh->nid == NID_modp_6144 || !BN_cmp(dh->p, &_bignum_modp_6144_p)) {
        nid = NID_modp_6144;
        q = &_bignum_modp_6144_q;
        length = 375;
    } else if (dh->nid == NID_modp_8192 || !BN_cmp(dh->p, &_bignum_modp_8192_p)) {
        nid = NID_modp_8192;
        q = &_bignum_modp_8192_q;
        length = 400;
    } else if (!FIPS_mode() && (dh->nid == NID_modp_1536 || !BN_cmp(dh->p, &_bignum_modp_1536_p))) {
        nid = NID_modp_1536;
        q = &_bignum_modp_1536_q;
        length = 175;
    } else {
        return NID_undef;
    }

    if (dh->q != NULL) {
        /* Check that q matches the known q. */
        if (BN_cmp(dh->q, q))
            return NID_undef;
    } else if (qout != NULL) {
        *qout = (BIGNUM *)q;
    }

    if (lout != NULL) {
        *lout = length;
    }
    return nid;
}

int DH_get_nid(const DH *dh)
{
    if (dh->nid != NID_undef) {
        return dh->nid;
    }
    return dh_match_group(dh, NULL, NULL);
}

void dh_cache_nid(DH *dh)
{
    dh->nid = dh_match_group(dh, NULL, &dh->length);
}

int dh_get_known_q(const DH *dh, BIGNUM **q)
{
    return dh_match_group(dh, q, NULL) != NID_undef;
}

