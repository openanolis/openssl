/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <time.h>
#include "internal/cryptlib.h"
#include <openssl/bn.h>
#include "dsa_local.h"

#ifdef OPENSSL_FIPS
# include <openssl/fips.h>
# include "crypto/fips.h"

static int fips_check_dsa(DSA *dsa)
{
    EVP_PKEY *pk;
    unsigned char tbs[] = "DSA Pairwise Check Data";
    int ret = 0;

    if ((pk = EVP_PKEY_new()) == NULL)
        goto err;

    EVP_PKEY_set1_DSA(pk, dsa);

    if (fips_pkey_signature_test(pk, tbs, -1, NULL, 0, NULL, 0, NULL))
        ret = 1;

 err:
    if (ret == 0) {
        FIPSerr(FIPS_F_FIPS_CHECK_DSA, FIPS_R_PAIRWISE_TEST_FAILED);
        fips_set_selftest_fail();
    }

    if (pk)
        EVP_PKEY_free(pk);

    return ret;
}

#endif

static int dsa_builtin_keygen(DSA *dsa);

int DSA_generate_key(DSA *dsa)
{
#ifdef OPENSSL_FIPS
    if (FIPS_mode() && !(dsa->meth->flags & DSA_FLAG_FIPS_METHOD)
        && !(dsa->flags & DSA_FLAG_NON_FIPS_ALLOW)) {
        DSAerr(DSA_F_DSA_GENERATE_KEY, DSA_R_NON_FIPS_DSA_METHOD);
        return 0;
    }
#endif
    if (dsa->meth->dsa_keygen)
        return dsa->meth->dsa_keygen(dsa);
    return dsa_builtin_keygen(dsa);
}

static int dsa_builtin_keygen(DSA *dsa)
{
    int ok = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *pub_key = NULL, *priv_key = NULL;

#ifdef OPENSSL_FIPS
    if (FIPS_mode() && !(dsa->flags & DSA_FLAG_NON_FIPS_ALLOW)
        && (BN_num_bits(dsa->p) < OPENSSL_DSA_FIPS_MIN_MODULUS_BITS_GEN)) {
        DSAerr(DSA_F_DSA_BUILTIN_KEYGEN, DSA_R_KEY_SIZE_TOO_SMALL);
        goto err;
    }
#endif

    if ((ctx = BN_CTX_new()) == NULL)
        goto err;

    if (dsa->priv_key == NULL) {
        if ((priv_key = BN_secure_new()) == NULL)
            goto err;
    } else
        priv_key = dsa->priv_key;

    do
        if (!BN_priv_rand_range(priv_key, dsa->q))
            goto err;
    while (BN_is_zero(priv_key)) ;

    if (dsa->pub_key == NULL) {
        if ((pub_key = BN_new()) == NULL)
            goto err;
    } else
        pub_key = dsa->pub_key;

    {
        BIGNUM *prk = BN_new();

        if (prk == NULL)
            goto err;
        BN_with_flags(prk, priv_key, BN_FLG_CONSTTIME);

        if (!BN_mod_exp(pub_key, dsa->g, prk, dsa->p, ctx)) {
            BN_free(prk);
            goto err;
        }
        /* We MUST free prk before any further use of priv_key */
        BN_free(prk);
    }

    dsa->priv_key = priv_key;
    dsa->pub_key = pub_key;
#ifdef OPENSSL_FIPS
    if (FIPS_mode() && !fips_check_dsa(dsa)) {
        dsa->pub_key = NULL;
        dsa->priv_key = NULL;
        goto err;
    }
#endif
    ok = 1;

 err:
    if (pub_key != dsa->pub_key)
        BN_free(pub_key);
    if (priv_key != dsa->priv_key)
        BN_free(priv_key);
    BN_CTX_free(ctx);
    return ok;
}
