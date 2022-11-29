/*
 * Copyright 2018-2019 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2018-2019, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/err.h>
#include <openssl/fips.h>
#include "crypto/fips.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>

#ifdef OPENSSL_FIPS
static int FIPS_selftest_tls1_prf(void)
{
    int ret = 0;
    EVP_KDF_CTX *kctx;
    unsigned char out[16];

    if ((kctx = EVP_KDF_CTX_new_id(EVP_KDF_TLS1_PRF)) == NULL) {
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_MD, EVP_sha256()) <= 0) {
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_TLS_SECRET,
                     "secret", (size_t)6) <= 0) {
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_ADD_TLS_SEED, "seed", (size_t)4) <= 0) {
        goto err;
    }
    if (EVP_KDF_derive(kctx, out, sizeof(out)) <= 0) {
        goto err;
    }

    {
        const unsigned char expected[sizeof(out)] = {
            0x8e, 0x4d, 0x93, 0x25, 0x30, 0xd7, 0x65, 0xa0,
            0xaa, 0xe9, 0x74, 0xc3, 0x04, 0x73, 0x5e, 0xcc
        };
        if (memcmp(out, expected, sizeof(expected))) {
            goto err;
        }
    }
    ret = 1;

err:
    if (!ret)
        FIPSerr(FIPS_F_FIPS_SELFTEST_TLS1_PRF, FIPS_R_SELFTEST_FAILED);
    EVP_KDF_CTX_free(kctx);
    return ret;
}

static int FIPS_selftest_hkdf(void)
{
    int ret = 0;
    EVP_KDF_CTX *kctx;
    unsigned char out[10];

    if ((kctx = EVP_KDF_CTX_new_id(EVP_KDF_HKDF)) == NULL) {
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_MD, EVP_sha256()) <= 0) {
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SALT, "salt", (size_t)4) <= 0) {
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_KEY, "secret", (size_t)6) <= 0) {
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_ADD_HKDF_INFO,
                     "label", (size_t)5) <= 0) {
        goto err;
    }
    if (EVP_KDF_derive(kctx, out, sizeof(out)) <= 0) {
        goto err;
    }

    {
        const unsigned char expected[sizeof(out)] = {
            0x2a, 0xc4, 0x36, 0x9f, 0x52, 0x59, 0x96, 0xf8, 0xde, 0x13
        };
        if (memcmp(out, expected, sizeof(expected))) {
            goto err;
        }
    }
    ret = 1;
err:
    if (!ret)
        FIPSerr(FIPS_F_FIPS_SELFTEST_HKDF, FIPS_R_SELFTEST_FAILED);
    EVP_KDF_CTX_free(kctx);
    return ret;
}

static int FIPS_selftest_sshkdf(void)
{
    int ret = 0;
    EVP_KDF_CTX *kctx;
    unsigned char out[32];
    const unsigned char input_key[] = {
        0x00, 0x00, 0x00, 0x80, 0x0f, 0xaa, 0x17, 0x2b,
        0x8c, 0x28, 0x7e, 0x37, 0x2b, 0xb2, 0x36, 0xad,
        0x34, 0xc7, 0x33, 0x69, 0x5c, 0x13, 0xd7, 0x7f,
        0x88, 0x2a, 0xdc, 0x0f, 0x47, 0xe5, 0xa7, 0xf6,
        0xa3, 0xde, 0x07, 0xef, 0xb1, 0x01, 0x20, 0x7a,
        0xa5, 0xd6, 0x65, 0xb6, 0x19, 0x82, 0x6f, 0x75,
        0x65, 0x91, 0xf6, 0x53, 0x10, 0xbb, 0xd2, 0xc9,
        0x2c, 0x93, 0x84, 0xe6, 0xc6, 0xa6, 0x7b, 0x42,
        0xde, 0xc3, 0x82, 0xfd, 0xb2, 0x4c, 0x59, 0x1d,
        0x79, 0xff, 0x5e, 0x47, 0x73, 0x7b, 0x0f, 0x5b,
        0x84, 0x79, 0x69, 0x4c, 0x3a, 0xdc, 0x19, 0x40,
        0x17, 0x04, 0x91, 0x2b, 0xbf, 0xec, 0x27, 0x04,
        0xd4, 0xd5, 0xbe, 0xbb, 0xfc, 0x1a, 0x7f, 0xc7,
        0x96, 0xe2, 0x77, 0x63, 0x4e, 0x40, 0x85, 0x18,
        0x51, 0xa1, 0x87, 0xec, 0x2d, 0x37, 0xed, 0x3f,
        0x35, 0x1c, 0x45, 0x96, 0xa5, 0xa0, 0x89, 0x29,
        0x16, 0xb4, 0xc5, 0x5f
    };
    const unsigned char xcghash[] = {
        0xa3, 0x47, 0xf5, 0xf1, 0xe1, 0x91, 0xc3, 0x5f,
        0x21, 0x2c, 0x93, 0x24, 0xd5, 0x86, 0x7e, 0xfd,
        0xf8, 0x30, 0x26, 0xbe, 0x62, 0xc2, 0xb1, 0x6a,
        0xe0, 0x06, 0xed, 0xb3, 0x37, 0x8d, 0x40, 0x06
    };
    const unsigned char session_id[] = {
        0x90, 0xbe, 0xfc, 0xef, 0x3f, 0xf8, 0xf9, 0x20,
        0x67, 0x4a, 0x9f, 0xab, 0x94, 0x19, 0x8c, 0xf3,
        0xfd, 0x9d, 0xca, 0x24, 0xa2, 0x1d, 0x3c, 0x9d,
        0xba, 0x39, 0x4d, 0xaa, 0xfb, 0xc6, 0x21, 0xed
    };


    if ((kctx = EVP_KDF_CTX_new_id(EVP_KDF_SSHKDF)) == NULL) {
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_MD, EVP_sha256()) <= 0) {
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_KEY, input_key,
                     sizeof(input_key)) <= 0) {
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SSHKDF_XCGHASH, xcghash,
                     sizeof(xcghash)) <= 0) {
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SSHKDF_SESSION_ID, session_id,
                     sizeof(session_id)) <= 0) {
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SSHKDF_TYPE, (int)'F') <= 0) {
        goto err;
    }
    if (EVP_KDF_derive(kctx, out, sizeof(out)) <= 0) {
        goto err;
    }

    {
        const unsigned char expected[sizeof(out)] = {
            0x14, 0x7a, 0x77, 0x14, 0x45, 0x12, 0x3f, 0x84,
            0x6d, 0x8a, 0xe5, 0x14, 0xd7, 0xff, 0x9b, 0x3c,
            0x93, 0xb2, 0xbc, 0xeb, 0x7c, 0x7c, 0x95, 0x00,
            0x94, 0x21, 0x61, 0xb8, 0xe2, 0xd0, 0x11, 0x0f
        };
        if (memcmp(out, expected, sizeof(expected))) {
            goto err;
        }
    }
    ret = 1;

err:
    if (!ret)
        FIPSerr(FIPS_F_FIPS_SELFTEST_SSHKDF, FIPS_R_SELFTEST_FAILED);
    EVP_KDF_CTX_free(kctx);
    return ret;
}

static int FIPS_selftest_pbkdf2(void)
{
    int ret = 0;
    EVP_KDF_CTX *kctx;
    unsigned char out[32];

    if ((kctx = EVP_KDF_CTX_new_id(EVP_KDF_PBKDF2)) == NULL) {
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_PASS, "password", (size_t)8) <= 0) {
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SALT, "salt", (size_t)4) <= 0) {
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_ITER, 2) <= 0) {
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_MD, EVP_sha256()) <= 0) {
        goto err;
    }
    if (EVP_KDF_derive(kctx, out, sizeof(out)) <= 0) {
        goto err;
    }

    {
        const unsigned char expected[sizeof(out)] = {
            0xae, 0x4d, 0x0c, 0x95, 0xaf, 0x6b, 0x46, 0xd3,
            0x2d, 0x0a, 0xdf, 0xf9, 0x28, 0xf0, 0x6d, 0xd0,
            0x2a, 0x30, 0x3f, 0x8e, 0xf3, 0xc2, 0x51, 0xdf,
            0xd6, 0xe2, 0xd8, 0x5a, 0x95, 0x47, 0x4c, 0x43
        };
        if (memcmp(out, expected, sizeof(expected))) {
            goto err;
        }
    }
    ret = 1;

err:
    if (!ret)
        FIPSerr(FIPS_F_FIPS_SELFTEST_PBKDF2, FIPS_R_SELFTEST_FAILED);
    EVP_KDF_CTX_free(kctx);
    return ret;
}

/* Test vector from RFC 8009 (AES Encryption with HMAC-SHA2 for Kerberos
 * 5) appendix A. */
static int FIPS_selftest_kbkdf(void)
{
    int ret = 0;
    EVP_KDF_CTX *kctx;
    char *label = "prf", *prf_input = "test";
    const unsigned char input_key[] = {
        0x37, 0x05, 0xD9, 0x60, 0x80, 0xC1, 0x77, 0x28,
        0xA0, 0xE8, 0x00, 0xEA, 0xB6, 0xE0, 0xD2, 0x3C,
    };
    const unsigned char output[] = {
        0x9D, 0x18, 0x86, 0x16, 0xF6, 0x38, 0x52, 0xFE,
        0x86, 0x91, 0x5B, 0xB8, 0x40, 0xB4, 0xA8, 0x86,
        0xFF, 0x3E, 0x6B, 0xB0, 0xF8, 0x19, 0xB4, 0x9B,
        0x89, 0x33, 0x93, 0xD3, 0x93, 0x85, 0x42, 0x95,
    };
    unsigned char result[sizeof(output)] = { 0 };

    if ((kctx = EVP_KDF_CTX_new_id(EVP_KDF_KB)) == NULL) {
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_KB_MAC_TYPE, EVP_KDF_KB_MAC_TYPE_HMAC) <= 0) {
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_MD, EVP_sha256()) <= 0) {
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_KEY, input_key, sizeof(input_key)) <= 0) {
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SALT, label, strlen(label)) <= 0) {
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_KB_INFO, prf_input, strlen(prf_input)) <= 0) {
        goto err;
    }
    ret = EVP_KDF_derive(kctx, result, sizeof(result)) > 0
        && memcmp(result, output, sizeof(output)) == 0;
err:
    if (!ret)
        FIPSerr(FIPS_F_FIPS_SELFTEST_KBKDF, FIPS_R_SELFTEST_FAILED);
    EVP_KDF_CTX_free(kctx);
    return ret;
}

static int FIPS_selftest_krb5kdf(void)
{
    int ret = 0;
    EVP_KDF_CTX *kctx;
    unsigned char out[16];
    const unsigned char key[] = {
        0x42, 0x26, 0x3C, 0x6E, 0x89, 0xF4, 0xFC, 0x28,
        0xB8, 0xDF, 0x68, 0xEE, 0x09, 0x79, 0x9F, 0x15
    };
    const unsigned char constant[] = {
        0x00, 0x00, 0x00, 0x02, 0x99
    };
    const unsigned char expected[sizeof(out)] = {
        0x34, 0x28, 0x0A, 0x38, 0x2B, 0xC9, 0x27, 0x69,
        0xB2, 0xDA, 0x2F, 0x9E, 0xF0, 0x66, 0x85, 0x4B
    };

    if ((kctx = EVP_KDF_CTX_new_id(EVP_KDF_KRB5KDF)) == NULL) {
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_CIPHER, EVP_aes_128_cbc()) <= 0) {
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_KEY, key, sizeof(key)) <= 0) {
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_KRB5KDF_CONSTANT, constant, sizeof(constant)) <= 0) {
        goto err;
    }

    ret =
        EVP_KDF_derive(kctx, out, sizeof(out)) > 0
        && memcmp(out, expected, sizeof(expected)) == 0;

err:
    if (!ret)
        FIPSerr(FIPS_F_FIPS_SELFTEST_KRB5KDF, FIPS_R_SELFTEST_FAILED);
    EVP_KDF_CTX_free(kctx);
    return ret;
}

static int FIPS_selftest_sskdf(void)
{
    int ret = 0;
    EVP_KDF_CTX *kctx;
    const unsigned char z[] = {
        0x6d,0xbd,0xc2,0x3f,0x04,0x54,0x88,0xe4,0x06,0x27,0x57,0xb0,0x6b,0x9e,
        0xba,0xe1,0x83,0xfc,0x5a,0x59,0x46,0xd8,0x0d,0xb9,0x3f,0xec,0x6f,0x62,
        0xec,0x07,0xe3,0x72,0x7f,0x01,0x26,0xae,0xd1,0x2c,0xe4,0xb2,0x62,0xf4,
        0x7d,0x48,0xd5,0x42,0x87,0xf8,0x1d,0x47,0x4c,0x7c,0x3b,0x18,0x50,0xe9
    };
    const unsigned char other[] = {
        0xa1,0xb2,0xc3,0xd4,0xe5,0x43,0x41,0x56,0x53,0x69,0x64,0x3c,0x83,0x2e,
        0x98,0x49,0xdc,0xdb,0xa7,0x1e,0x9a,0x31,0x39,0xe6,0x06,0xe0,0x95,0xde,
        0x3c,0x26,0x4a,0x66,0xe9,0x8a,0x16,0x58,0x54,0xcd,0x07,0x98,0x9b,0x1e,
        0xe0,0xec,0x3f,0x8d,0xbe
    };
    const unsigned char expected[] = {
        0xa4,0x62,0xde,0x16,0xa8,0x9d,0xe8,0x46,0x6e,0xf5,0x46,0x0b,0x47,0xb8
    };
    unsigned char out[14];

    kctx = EVP_KDF_CTX_new_id(EVP_KDF_SS);

    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_MD, EVP_sha224()) <= 0) {
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_KEY, z, sizeof(z)) <= 0) {
        goto err;
    }
    if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SSKDF_INFO, other,
                     sizeof(other)) <= 0) {
        goto err;
    }
    if (EVP_KDF_derive(kctx, out, sizeof(out)) <= 0) {
        goto err;
    }

    if (memcmp(out, expected, sizeof(expected)))
        goto err;
    ret = 1;

err:
    if (!ret)
        FIPSerr(FIPS_F_FIPS_SELFTEST_SSKDF, FIPS_R_SELFTEST_FAILED);
    EVP_KDF_CTX_free(kctx);
    return ret;
}

int FIPS_selftest_kdf(void)
{
    return FIPS_selftest_tls1_prf()
        && FIPS_selftest_hkdf()
        && FIPS_selftest_sshkdf()
        && FIPS_selftest_pbkdf2()
        && FIPS_selftest_kbkdf()
        && FIPS_selftest_krb5kdf()
        && FIPS_selftest_sskdf();
}

#endif
