/* tpm_io_barebox.c
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

/* This example shows IO interfaces for Barebox */

#include "tpm_io.h"
#include "wolftpm/tpm2.h"
#include "wolftpm/tpm2_tis.h"

/******************************************************************************/
/* --- BEGIN IO Callback Logic -- */
/******************************************************************************/

/* Use the max speed by default - see tpm2_types.h for chip specific max values
 */
#ifndef TPM2_SPI_HZ
#define TPM2_SPI_HZ TPM2_SPI_MAX_HZ
#endif
#include "spi.h"

extern L4::Cap<SPI> spi;

int TPM2_IoCb_L4_SPI(TPM2_CTX *ctx, const byte *txBuf, byte *rxBuf,
                          word16 xferSz, void *userCtx) {

  L4::Ipc::Array<const l4_uint8_t, l4_uint32_t> send = 
      L4::Ipc::Array<const l4_uint8_t, l4_uint32_t>(xferSz,
                                                    static_cast<const unsigned char*>(txBuf));
  L4::Ipc::Array<l4_uint8_t, l4_uint32_t> recv = 
      L4::Ipc::Array<l4_uint8_t, l4_uint32_t>(xferSz, 
                                              static_cast<unsigned char*>(rxBuf));

  int ret = spi->transfer(send, recv, xferSz);
  
  if (ret != L4_EOK)
    return TPM_RC_FAILURE;
  
  #ifdef DEBUG
  printf("txbuf %x rxbuf %x xfersize %d\n", txBuf, txBuf, xferSz);
  #endif
  return TPM_RC_SUCCESS;
}

/******************************************************************************/
/* --- END IO Callback Logic -- */
/******************************************************************************/
