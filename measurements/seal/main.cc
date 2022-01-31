#include <ostream>
#include <string>

#include <time.h>
#include <cstdio>
#include "wolftpm/tpm2_wrap.h"
#include "pcr.h"
#include "tpm_io.h"
#include "tpm_test.h"

#include "seal.h"
#include "tpm_io.h"
#include "tpm_test.h"
#include "tpm_test_keys.h"


#ifndef NUM_OF_RUNS
#define NUM_OF_RUNS 1000
#endif


unsigned long times[NUM_OF_RUNS];

int main(void) {

    #ifdef USE_GETTIME
    for(int i = 0; i< NUM_OF_RUNS; i++) { times[i] = 0;}
    struct timespec start, end;
    #else
    unsigned long long start = 0, end = 0;
    #endif
 int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY storage; /* SRK */
    WOLFTPM2_KEYBLOB newKey;
    TPMT_PUBLIC publicTemplate;
    TPM_ALG_ID paramEncAlg = TPM_ALG_NULL;
    WOLFTPM2_SESSION tpmSession;
    TPM2B_AUTH auth;
    char defaultData[] = "My1Pass2Phrase3";
    char *userData = defaultData;


    void* userCtx = NULL;    
    for(int count = 0; count < NUM_OF_RUNS; count++) {
        //init
       XMEMSET(&storage, 0, sizeof(storage));
    XMEMSET(&newKey, 0, sizeof(newKey));
    XMEMSET(&tpmSession, 0, sizeof(tpmSession));
    XMEMSET(&auth, 0, sizeof(auth));

        rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("\nwolfTPM2_Init failed\n");
        goto exit;
    }
    
     #ifdef USE_GETTIME
    clock_gettime(CLOCK_REALTIME, &start);
    #else 
    asm volatile("mrs %0, CNTVCT_EL0" : "=r" (start));
#endif
    //meassured code    

     /* get SRK */
    rc = getPrimaryStoragekey(&dev, &storage, TPM_ALG_RSA);
    if (rc != 0) goto exit;

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

    wolfTPM2_GetKeyTemplate_KeySeal(&publicTemplate, TPM_ALG_SHA256);

    /* set session for authorization key */
    auth.size = (int)sizeof(gKeyAuth)-1;
    XMEMCPY(auth.buffer, gKeyAuth, auth.size);

    rc = wolfTPM2_CreateKeySeal(&dev, &newKey, &storage.handle,
                                &publicTemplate, auth.buffer, auth.size,
                                (BYTE*)userData, (int)strlen(userData));
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_CreateKey failed\n");
        goto exit;
    }

    #ifdef USE_GETTIME
    clock_gettime(CLOCK_REALTIME, &end);
    #else 
    asm volatile("mrs %0, CNTVCT_EL0" : "=r" (end));
    #endif
    //final
exit:

    if (rc != 0) {
        printf("\nFailure 0x%x: %s\n\n", rc, wolfTPM2_GetRCString(rc));
    }

    /* Close handles */
    wolfTPM2_UnloadHandle(&dev, &storage.handle);
    wolfTPM2_UnloadHandle(&dev, &newKey.handle);
    wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);

    wolfTPM2_Cleanup(&dev);
       
        times[count] = ((end.tv_sec * 1000000000) + end.tv_nsec) - ((start.tv_sec * 1000000000) + start.tv_nsec);
    }
    
    for (int i =0; i<NUM_OF_RUNS; i++) {
        printf("%d, %lu; ", i,times[i]);
    }

    puts("");
    return 0;
}
