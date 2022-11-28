/* ====================================================================
 * Copyright (c) 2003 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/opensslconf.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

int main(int argc, char **argv)
{
#ifdef OPENSSL_FIPS
    static char key[] = "orboDeJITITejsirpADONivirpUkvarP";
    int n, binary = 0;

    if (argc < 2) {
        fprintf(stderr, "%s [<file>]+\n", argv[0]);
        exit(1);
    }

    n = 1;
    if (!strcmp(argv[n], "-binary")) {
        n++;
        binary = 1;             /* emit binary fingerprint... */
    }

    for (; n < argc; ++n) {
        FILE *f = fopen(argv[n], "rb");
        HMAC_CTX *hmac_ctx;
        unsigned char mac[EVP_MAX_MD_SIZE];
        unsigned int len;
        unsigned int i;

        if (!f) {
            perror(argv[n]);
            exit(2);
        }
        hmac_ctx = HMAC_CTX_new();
        if (!hmac_ctx)
            exit(3);

        if (HMAC_Init_ex(hmac_ctx, key, strlen(key), EVP_sha256(), NULL) <= 0) {
            fprintf(stderr, "HMAC SHA256 initialization failed.\n");
            exit(4);
        }

        for (;;) {
            unsigned char buf[1024];
            size_t l = fread(buf, 1, sizeof buf, f);

            if (l == 0) {
                if (ferror(f)) {
                    perror(argv[n]);
                    exit(3);
                } else
                    break;
            }
            if (HMAC_Update(hmac_ctx, buf, l) <= 0) {
                fprintf(stderr, "HMAC_Update() failed.\n");
                exit(4);
            }
        }
        if (HMAC_Final(hmac_ctx, mac, &len) <= 0) {
            fprintf(stderr, "HMAC_Final() failed.\n");
            exit(4);
        }

        if (binary) {
            fwrite(mac, len, 1, stdout);
            break;              /* ... for single(!) file */
        }

/*      printf("HMAC-SHA1(%s)= ",argv[n]); */
        for (i = 0; i < len; ++i)
            printf("%02x", mac[i]);
        printf("\n");
    }
#endif
    return 0;
}
