/* tpm_io.c
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

/* This source code provides example TPM IO HAL Callbacks for various platforms
 *
 * NB: wolfTPM projects requires only #include "tpm_io.h" and
 *     the appropriate defines for the platform in use.
 *
 *     Use cases that do not require an IO callback:
 *      - Native Linux
 *      - Native Windows
 *      - TPM Simulator
 *
 */

#include "tpm_io.h"
#include "wolftpm/tpm2.h"
#include "wolftpm/tpm2_tis.h"

/******************************************************************************/
/* --- BEGIN IO Callback Logic -- */
/******************************************************************************/

/* Native Windows, native Linux and TPM Simulator do not need an IO callback */
#if !(defined(WOLFTPM_LINUX_DEV) || defined(WOLFTPM_SWTPM) ||                  \
      defined(WOLFTPM_WINAPI))

/* Set WOLFTPM_INCLUDE_IO_FILE so each .c is built here and not compiled
 * directly */
#define WOLFTPM_INCLUDE_IO_FILE
#include "tpm_io_l4.cc"

static int TPM2_IoCb_SPI(TPM2_CTX *ctx, const byte *txBuf, byte *rxBuf,
                         word16 xferSz, void *userCtx) {
  int ret = TPM_RC_FAILURE;

  ret = TPM2_IoCb_L4_SPI(ctx, txBuf, rxBuf, xferSz, userCtx);

  (void)txBuf;
  (void)rxBuf;
  (void)xferSz;
  (void)userCtx;

  (void)ctx;

  return ret;
}

#ifdef WOLFTPM_ADV_IO
int TPM2_IoCb(TPM2_CTX *ctx, int isRead, word32 addr, byte *buf, word16 size,
              void *userCtx) {
  int ret = TPM_RC_FAILURE;
#if !defined(WOLFTPM_I2C)
  byte txBuf[MAX_SPI_FRAMESIZE + TPM_TIS_HEADER_SZ];
  byte rxBuf[MAX_SPI_FRAMESIZE + TPM_TIS_HEADER_SZ];
#endif

#ifdef WOLFTPM_DEBUG_IO
  printf("TPM2_IoCb (Adv): Read %d, Addr %x, Size %d\n", isRead ? 1 : 0, addr,
         size);
  if (!isRead) {
    printf("Write Size %d\n", size);
    TPM2_PrintBin(buf, size);
  }
#endif

#if defined(WOLFTPM_I2C)
#if defined(__linux__)
  /* Use Linux I2C */
  ret = TPM2_IoCb_Linux_I2C(ctx, isRead, addr, buf, size, userCtx);
#elif defined(WOLFSSL_STM32_CUBEMX)
  /* Use STM32 CubeMX HAL for I2C */
  ret = TPM2_IoCb_STCubeMX_I2C(ctx, isRead, addr, buf, size, userCtx);
#else
  /* TODO: Add your platform here for HW I2C interface */
  printf("Add your platform here for HW I2C interface\n");
  (void)isRead;
  (void)addr;
  (void)buf;
  (void)size;
  (void)userCtx;
#endif
#else
  /* Build TPM header */
  txBuf[1] = (addr >> 16) & 0xFF;
  txBuf[2] = (addr >> 8) & 0xFF;
  txBuf[3] = (addr)&0xFF;
  if (isRead) {
    txBuf[0] = TPM_TIS_READ | ((size & 0xFF) - 1);
    XMEMSET(&txBuf[TPM_TIS_HEADER_SZ], 0, size);
  } else {
    txBuf[0] = TPM_TIS_WRITE | ((size & 0xFF) - 1);
    XMEMCPY(&txBuf[TPM_TIS_HEADER_SZ], buf, size);
  }
  XMEMSET(rxBuf, 0, sizeof(rxBuf));

  ret = TPM2_IoCb_SPI(ctx, txBuf, rxBuf, size + TPM_TIS_HEADER_SZ, userCtx);

  if (isRead) {
    XMEMCPY(buf, &rxBuf[TPM_TIS_HEADER_SZ], size);
  }
#endif

#ifdef WOLFTPM_DEBUG_IO
  if (isRead) {
    printf("Read Size %d\n", size);
    TPM2_PrintBin(buf, size);
  }
#endif

  (void)ctx;

  return ret;
}

#else

/* IO Callback */
int TPM2_IoCb(TPM2_CTX *ctx, const byte *txBuf, byte *rxBuf, word16 xferSz,
              void *userCtx) {
  int ret = TPM_RC_FAILURE;

  ret = TPM2_IoCb_SPI(ctx, txBuf, rxBuf, xferSz, userCtx);
  #ifdef WOLFTPM_DEBUG
  printf("TPM2_IoCb: Ret %d, Sz %d\n", ret, xferSz);
  TPM2_PrintBin(txBuf, xferSz);
  TPM2_PrintBin(rxBuf, xferSz);
  #endif
  (void)ctx;

  return ret;
}

#endif /* WOLFTPM_ADV_IO */
#endif /* !(WOLFTPM_LINUX_DEV || WOLFTPM_SWTPM || WOLFTPM_WINAPI) */

/******************************************************************************/
/* --- END IO Callback Logic -- */
/******************************************************************************/
