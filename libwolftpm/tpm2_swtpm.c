/* tpm2_swtpm.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */



/**
 * This implements a subset of TPM TCP protocol as described in
 * "TPM-Rev-2.0-Part-4-Supporting-Routines-01.38-code"
 *
 * This is intended for testing with a simulator such as
 * http://ibmswtpm.sourceforge.net/ or
 * https://github.com/stefanberger/swtpm
 *
 * See docs/SWTPM.md
 */

#ifdef WOLFTPM_SWTPM
#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_swtpm.h>
#include <wolftpm/tpm2_packet.h>

#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

static L4::Cap<TPM> tpm;

static TPM_RC SwTpmTransmit(TPM2_CTX* ctx, const void* buffer, ssize_t bufSz)
{
    if(bufSz < 0) {
        return TPM_RC_FAILURE;
    }
    L4::Ipc_Array<l4_uint8_t, l4_uint32_t> transfer = L4::Ipc_Array<l4_uint8_t, l4_uint32_t>(&buffer, bufSz);
    return vtpm->write(transfer);
}

static TPM_RC SwTpmReceive(TPM2_CTX* ctx, void* buffer, size_t rxSz)
{
    if(bufSz < 0) {
        return TPM_RC_FAILURE;
    }
    L4::Ipc_Array<l4_uint8_t, l4_uint32_t> transfer = L4::Ipc_Array<l4_uint8_t, l4_uint32_t>(&buffer, bufSz);
    return vtpm->read(transfer);
}

static TPM_RC SwTpmConnect(TPM2_CTX* ctx, const char* host, const char* port)
{   
    tpm = chkcap(L4Re::Env->env()->get_cap("vtpm"), "failed to get vtpm capability");

    //init tpm object
}

static TPM_RC SwTpmDisconnect(TPM2_CTX* ctx)
{
    return TPM_RC_SUCESS;
}

/* Talk to a TPM through socket
 * return TPM_RC_SUCCESS on success,
 *        SOCKET_ERROR_E on socket errors,
 *        TPM_RC_FAILURE on other errors
 */
int TPM2_SWTPM_SendCommand(TPM2_CTX* ctx, TPM2_Packet* packet)
{
    int rc = TPM_RC_FAILURE;
    int rspSz = 0;
    uint32_t tss_word;

    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }

    if (ctx->tcpCtx.fd < 0) {
        rc = SwTpmConnect(ctx, TPM2_SWTPM_HOST, TPM2_SWTPM_PORT);
    }

#ifdef WOLFTPM_DEBUG_VERBOSE
    printf("Command size: %d\n", packet->pos);
    TPM2_PrintBin(packet->buf, packet->pos);
#endif

    /* send start */
    tss_word = TPM2_Packet_SwapU32(TPM_SEND_COMMAND);
    if (rc == TPM_RC_SUCCESS) {
        rc = SwTpmTransmit(ctx, &tss_word, sizeof(uint32_t));
    }

    /* locality */
    if (rc == TPM_RC_SUCCESS) {
        rc = SwTpmTransmit(ctx, &ctx->locality, sizeof(uint8_t));
    }

    /* buffer size */
    tss_word = TPM2_Packet_SwapU32(packet->pos);
    if (rc == TPM_RC_SUCCESS) {
        rc = SwTpmTransmit(ctx, &tss_word, sizeof(uint32_t));
    }

    /* Send the TPM command buffer */
    if (rc == TPM_RC_SUCCESS) {
        rc = SwTpmTransmit(ctx, packet->buf, packet->pos);
    }

    /* receive response */
    if (rc == TPM_RC_SUCCESS) {
        rc = SwTpmReceive(ctx, &tss_word, sizeof(uint32_t));
        rspSz = TPM2_Packet_SwapU32(tss_word);
        if (rspSz > packet->size) {
            #ifdef WOLFTPM_DEBUG_VERBOSE
            printf("Response size(%d) larger than command buffer(%d)\n",
                   rspSz, packet->pos);
            #endif
            rc = SOCKET_ERROR_E;
        }
    }

    /* This performs a blocking read and could hang. This means a
     * misbehaving actor on the other end of the socket
     */
    if (rc == TPM_RC_SUCCESS) {
        rc = SwTpmReceive(ctx, packet->buf, rspSz);
    }

    /* receive ack */
    if (rc == TPM_RC_SUCCESS) {
        rc = SwTpmReceive(ctx, &tss_word, sizeof(uint32_t));
        tss_word = TPM2_Packet_SwapU32(tss_word);
        #ifdef WOLFTPM_DEBUG
        if (tss_word != 0) {
            printf("SWTPM ack %d\n", tss_word);
        }
        #endif
    }


#ifdef WOLFTPM_DEBUG_VERBOSE
    if (rspSz > 0) {
        printf("Response size: %d\n", rspSz);
        TPM2_PrintBin(packet->buf, rspSz);
    }
#endif

    if (ctx->tcpCtx.fd >= 0) {
        TPM_RC rc_disconnect = SwTpmDisconnect(ctx);
        if (rc == TPM_RC_SUCCESS) {
            rc = rc_disconnect;
        }
    }

    return rc;
}
#endif /* WOLFTPM_SWTPM */
