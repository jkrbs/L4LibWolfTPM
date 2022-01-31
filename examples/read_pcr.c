/* read.c
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
 *
 * This file is part of wolfTPM.
 *
 * wolfTPM is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfTPM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* This is a helper tool for reading the value of a TPM2.0 PCR */

#include <wolftpm/tpm2_wrap.h>

#ifndef WOLFTPM2_NO_WRAPPER

#ifndef WOLFTPM2_NO_WOLFCRYPT
#include <wolfssl/wolfcrypt/hash.h>
#endif

#include <examples/pcr/pcr.h>
#include <examples/tpm_io.h>
#include <examples/tpm_test.h>

#include <stdio.h>
#include <stdlib.h> /* atoi */


/******************************************************************************/
/* --- BEGIN TPM2.0 PCR Read example tool  -- */
/******************************************************************************/

static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/pcr/read [pcr]\n");
    printf("* pcr: PCR index between 0-23 (default %d)\n", TPM2_TEST_PCR);
    printf("Demo usage without parameters, reads PCR%d and prints its value\n",
        TPM2_TEST_PCR);
}

int TPM2_Read_Test(void* userCtx, int argc, char *argv[])
{
    int rc = -1;
    int pcrIndex = TPM2_TEST_PCR;
    WOLFTPM2_DEV dev;
    TPM2B_DIGEST pcrValue;

    if (argc >= 2) {
        if (XSTRNCMP(argv[1], "-?", 2) == 0 ||
            XSTRNCMP(argv[1], "-h", 2) == 0 ||
            XSTRNCMP(argv[1], "--help", 6) == 0) {
            usage();
            return 0;
        }

        if (argv[1][0] != '-') {
            pcrIndex = atoi(argv[1]);
            if (pcrIndex < (int)PCR_FIRST || pcrIndex > (int)PCR_LAST) {
                printf("PCR index is out of range (0-23)\n");
                usage();
                return 0;
            }
        }
    }

    printf("Demo how to read a PCR value (TPM2.0 measurement)\n");
    printf("\tPCR Index: %d\n", pcrIndex);

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_Init failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("wolfTPM2_Init: success\n");

/*
    XMEMSET(&cmdIn.pcrRead, 0, sizeof(cmdIn.pcrRead));
    TPM2_SetupPCRSel(&cmdIn.pcrRead.pcrSelectionIn,
        TEST_WRAP_DIGEST, pcrIndex);
    rc = TPM2_PCR_Read(&cmdIn.pcrRead, &cmdOut.pcrRead);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_PCR_Read failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
*/

    rc = wolfTPM2_ReadPCR(&dev, pcrIndex, TEST_WRAP_DIGEST, pcrValue.buffer, (int*)&pcrValue.size);
    if (rc != TPM_RC_SUCCESS ) {
        printf("wolfTPM2_PCR_Read failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("wolfTPM2_PCR_Read: success\n");

exit:

    wolfTPM2_Cleanup(&dev);

    return rc;
}

/******************************************************************************/
/* --- END TPM2.0 PCR Read example tool -- */
/******************************************************************************/

#endif /* !WOLFTPM2_NO_WRAPPER */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = -1;

#ifndef WOLFTPM2_NO_WRAPPER
    rc = TPM2_Read_Test(NULL, argc, argv);
#else
    printf("Wrapper code not compiled in\n");
    (void)argc;
    (void)argv;
#endif /* !WOLFTPM2_NO_WRAPPER */

    return rc;
}
#endif
