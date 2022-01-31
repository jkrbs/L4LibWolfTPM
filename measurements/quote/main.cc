/* quote.c
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

/* This example shows how to generate a TPM2.0 Quote that holds a signed
 * PCR measurement. PCR values are used as basis for system integrity.
 */

#include <wolftpm/tpm2_wrap.h>
#include "tpm_test.h"
#include "tpm_io.h"
#include <stdio.h>
#include <stdlib.h> /* atoi */
#include "tpm_test.h"
#include "tpm_test_keys.h"
#include "time.h"

#ifndef NUM_OF_RUNS
#define NUM_OF_RUNS 1000
#endif


unsigned long times[NUM_OF_RUNS];


int TPM2_Quote_Test(void* userCtx, int argc, char *argv[])
{
    #ifdef use_gettime
    for(int i = 0; i< num_of_runs; i++) { times[i] = 0;}
    struct timespec start, end;
    #else
    unsigned long long start = 0, end = 0;
    #endif

    int pcrIndex = TPM2_TEST_PCR, rc = -1;
    BYTE *data = NULL;
    int dataSz;
    WOLFTPM2_DEV dev;
    TPMS_ATTEST attestedData;
    TPMI_ALG_PUBLIC alg = TPM_ALG_RSA; /* TPM_ALG_ECC */
    WOLFTPM2_KEY storage; /* SRK */
    WOLFTPM2_KEY aik;  /* AIK */
    union {
        Quote_In quoteAsk;
        byte maxInput[MAX_COMMAND_SIZE];
    } cmdIn;
    union {
        Quote_Out quoteResult;
        byte maxOutput[MAX_RESPONSE_SIZE];
    } cmdOut;
    TPM_ALG_ID paramEncAlg = TPM_ALG_NULL;
    WOLFTPM2_SESSION tpmSession;
    XMEMSET(&storage, 0, sizeof(storage));
    XMEMSET(&aik, 0, sizeof(aik));
    XMEMSET(&tpmSession, 0, sizeof(tpmSession));

    printf("PCR Quote example - Demo of signed PCR measurement\n");
    printf("\tPCR Index: %d\n", pcrIndex);
    printf("\tUse %s SRK/AIK\n", TPM2_GetAlgName(alg));
    printf("\tUse Parameter Encryption: %s\n", TPM2_GetAlgName(paramEncAlg));

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_Init failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("wolfTPM2_Init: success\n");

    /* get SRK */
    rc = getPrimaryStoragekey(&dev, &storage, alg);
    if (rc != 0) goto exit;

    /* Create key for Attestation purposes */
    rc = wolfTPM2_CreateAndLoadAIK(&dev, &aik, alg, &storage,
        (const byte*)gUsageAuth, sizeof(gUsageAuth)-1);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_CreateAndLoadAIK failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("wolfTPM2_CreateAndLoadAIK: AIK 0x%x (%d bytes)\n",
        (word32)aik.handle.hndl, aik.pub.size);

    if (paramEncAlg != TPM_ALG_NULL) {
        /* Start an authenticated session (salted / unbound) with parameter encryption */
        rc = wolfTPM2_StartSession(&dev, &tpmSession, &storage, NULL,
            TPM_SE_HMAC, paramEncAlg);
        if (rc != 0) goto exit;
        printf("TPM2_StartAuthSession: sessionHandle 0x%x\n",
            (word32)tpmSession.handle.hndl);

        /* set session for authorization of the storage key */
        rc = wolfTPM2_SetAuthSession(&dev, 1, &tpmSession,
            (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt | TPMA_SESSION_continueSession));
        if (rc != 0) goto exit;
    }

    /* set auth for using the AIK */
    wolfTPM2_SetAuthHandle(&dev, 0, &aik.handle);

    /* Prepare Quote request */
    XMEMSET(&cmdIn.quoteAsk, 0, sizeof(cmdIn.quoteAsk));
    XMEMSET(&cmdOut.quoteResult, 0, sizeof(cmdOut.quoteResult));
    cmdIn.quoteAsk.signHandle = aik.handle.hndl;
    cmdIn.quoteAsk.inScheme.scheme = alg == TPM_ALG_RSA ? TPM_ALG_RSASSA : TPM_ALG_ECDSA;
    cmdIn.quoteAsk.inScheme.details.any.hashAlg = TPM_ALG_SHA256;
    cmdIn.quoteAsk.qualifyingData.size = 0; /* optional */
    /* Choose PCR for signing */
    TPM2_SetupPCRSel(&cmdIn.quoteAsk.PCRselect, TPM_ALG_SHA256, pcrIndex);

    /* Get the PCR measurement signed by the TPM using the AIK key */

    //start measurement
    #ifdef USE_GETTIME
        clock_gettime(CLOCK_REALTIME, &start);
    #endif
    rc = TPM2_Quote(&cmdIn.quoteAsk, &cmdOut.quoteResult);

    //end measurement
    
    #ifdef USE_GETTIME
        clock_gettime(CLOCK_REALTIME, &end);
    #endif
 
    
    times[count] = ((end.tv_sec * 1000000000) + end.tv_nsec) - ((start.tv_sec * 1000000000) + start.tv_nsec);
    
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_Quote failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_Quote: success\n");

    rc = TPM2_ParseAttest(&cmdOut.quoteResult.quoted, &attestedData);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_Packet_ParseAttest failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    if (attestedData.magic != TPM_GENERATED_VALUE) {
        printf("\tError, attested data not generated by the TPM = 0x%X\n",
            attestedData.magic);
    }

    /* Save quote blob to the disk */
    data = (UINT8*)&cmdOut.quoteResult.quoted;
    data += sizeof(UINT16); /* skip the size field of TPMS_ATTEST */
    dataSz = (int)sizeof(TPMS_ATTEST) - sizeof(UINT16);
    printf("Quote Blob %d\n", dataSz);
    TPM2_PrintBin(data, dataSz);
    (void)data;
    (void)dataSz;

    printf("TPM with signature attests (type 0x%x):\n", attestedData.type);
    printf("\tTPM signed %lu count of PCRs\n",
        (unsigned long)attestedData.attested.quote.pcrSelect.count);
#ifdef DEBUG_WOLFTPM
    printf("\tPCR digest:\n");
    TPM2_PrintBin(attestedData.attested.quote.pcrDigest.buffer,
        attestedData.attested.quote.pcrDigest.size);
    printf("\tTPM generated signature:\n");
    TPM2_PrintBin(cmdOut.quoteResult.signature.signature.rsassa.sig.buffer,
        cmdOut.quoteResult.signature.signature.rsassa.sig.size);
#endif

exit:

    /* Close key handles */
    wolfTPM2_UnloadHandle(&dev, &aik.handle);
    wolfTPM2_UnloadHandle(&dev, &storage.handle);
    wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);

    wolfTPM2_Cleanup(&dev);
    return rc;
}

/******************************************************************************/
/* --- END TPM2.0 Quote Test -- */
/******************************************************************************/


int main(int argc, char *argv[])
{
    int rc = -1;

    rc = TPM2_Quote_Test(NULL, argc, argv);
    for (int i =0; i<NUM_OF_RUNS; i++) {
        printf("%d, %lu; ", i,times[i]);
    }

    puts("");
    return 0;

        return rc;
}
