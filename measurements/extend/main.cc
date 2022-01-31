#include <ostream>
#include <string>

#include <time.h>
#include <cstdio>
#include "wolftpm/tpm2_wrap.h"
#include "pcr.h"
#include "tpm_io.h"
#include "tpm_test.h"

#ifndef NUM_OF_RUNS
#define NUM_OF_RUNS 10
#endif


int main(void) {

    struct timespec start, end;   
    unsigned long long start_timer = 0, end_timer = 0;

    for(int count = 0; count < NUM_OF_RUNS; count++) {
        //init
         int i, pcrIndex = 13, rc = -1;
    WOLFTPM2_DEV dev;
void* userCtx = NULL;    
    /* Arbitrary user data provided through a file */
    union {
        PCR_Extend_In pcrExtend;
        PCR_Read_In pcrRead;
        byte maxInput[MAX_COMMAND_SIZE];
    } cmdIn;
    union {
        PCR_Read_Out pcrRead;
        byte maxOutput[MAX_RESPONSE_SIZE];
    } cmdOut;
  
         rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_Init failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        continue;
    }

        XMEMSET(&cmdIn.pcrExtend, 0, sizeof(cmdIn.pcrExtend));
    cmdIn.pcrExtend.pcrHandle = pcrIndex;
    cmdIn.pcrExtend.digests.count = 1;
    cmdIn.pcrExtend.digests.digests[0].hashAlg = TPM_ALG_SHA256;
        
        for (i=0; i<TPM_SHA256_DIGEST_SIZE; i++) {
            cmdIn.pcrExtend.digests.digests[0].digest.H[i] = i;
        } 


        //meassured code    
        clock_gettime(CLOCK_REALTIME, &start);
        asm volatile("mrs %0, CNTVCT_EL0" : "=r" (start_timer));
        rc = TPM2_PCR_Extend(&cmdIn.pcrExtend);
   
        asm volatile("mrs %0, CNTVCT_EL0" : "=r" (end_timer));
        
        clock_gettime(CLOCK_REALTIME, &end);
        if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_PCR_Extend failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
            continue;
        }


        XMEMSET(&cmdIn.pcrRead, 0, sizeof(cmdIn.pcrRead));
    TPM2_SetupPCRSel(&cmdIn.pcrRead.pcrSelectionIn,
        TEST_WRAP_DIGEST, pcrIndex);
    rc = TPM2_PCR_Read(&cmdIn.pcrRead, &cmdOut.pcrRead);
        //final
        wolfTPM2_Cleanup(&dev);
        
        unsigned long duration = ((end.tv_sec * 1000000000) + end.tv_nsec) - ((start.tv_sec * 1000000000) + start.tv_nsec);
        printf("start: nsec: %lu, sec: %lu\n", start.tv_nsec, start.tv_sec);
        printf("end: nsec: %lu, sec: %lu\n", end.tv_nsec, end.tv_sec);
        printf("timer: strt %llu, end %llu, duration %llu\n", start_timer, end_timer, end_timer-start_timer);
        printf("count = %d, duration = %lu; \n", count, duration);
        fflush(stdout);
    }
    puts("");
    return 0;
}
