/* max3266x.h
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifndef _WOLFPORT_MAX3266X_H_
#define _WOLFPORT_MAX3266X_H_
#include <wolfssl/wolfcrypt/settings.h>
#warning "INSIDE MAX32666x.h"
#if defined(WOLFSSL_MAX32665) || defined(WOLFSSL_MAX32666)

#include <wolfssl/wolfcrypt/types.h>
#include "tpu.h"    /* SDK Drivers for the TPU unit */
                    /* Handles AES, SHA, TRNG and   */
                    /* MAA driver to accelerate RSA/ECDSA   */
#include "mxc_errors.h" /* ERROR Codes */
#include "mxc_device.h"
#include "board.h"
#include "max32665.h"

#if !defined(MAX3266X_RNG) && !defined(MAX3266X_AESCBC) && \
        !defined(MAX3266X_AESGCM) && !defined(MAX3266X_SHA256) && \
        !defined(MAX3266X_ECDSA) && !defined(MAX3266X_RSA)
    #define MAX3266X_RNG    /* TPU */
    #define MAX3266X_AES /* TPU */
    #define MAX3266X_SHA256 /* TPU */
    #define MAX3266X_ECDSA  /* MAA */
    #define MAX3266X_RSA    /* MAA */
#endif


/* Variable Definitions */

#ifdef __cplusplus
    extern "C" {
#endif

    int wc_MXC_TPU_Init(void);
    int wc_MXC_TPU_Shutdown(void);
    //int wc_MXC_AesSetKey(Aes* aes, byte* userKey, word32 keylen);

#ifdef MAX3266X_RNG
    int wc_MXC_TRNG_Random(byte* output, word32 sz);
#endif


#ifdef __cplusplus
    }
#endif

#endif /* WOLFSSL_MAX32665 || WOLFSSL_MAX32666 */
#endif /* _WOLFPORT_MAX3266X_H_ */
