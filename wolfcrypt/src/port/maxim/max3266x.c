/* max3266x.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/port/maxim/max3266x.h>
#warning "Inside max3266x.c"
#if defined(WOLFSSL_MAX32665) ||  defined(WOLFSSL_MAX32666)

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include <stdint.h>
#include <wolfssl/internal.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfcrypt/src/misc.c>

int wc_MXC_TPU_Init(void)
{
    /* Initialize the TPU device*/
    if(MXC_TPU_Init(MXC_SYS_PERIPH_CLOCK_TRNG) != EXIT_SUCCESS){
        /* TODO Add wolfSSL debugging */
        printf("Device did not initialize\n");
        return RNG_FAILURE_E;
    }

    return EXIT_SUCCESS;
}

int wc_MXC_TPU_Shutdown(void)
{
    /* Shutdown the TPU device*/
    if(MXC_TPU_Shutdown(MXC_SYS_PERIPH_CLOCK_TRNG) != EXIT_SUCCESS){
        /* TODO Add wolfSSL debugging */
        printf("Device did not shutdown\n");
        return RNG_FAILURE_E;
    }

    return EXIT_SUCCESS;
}

/*
int wc_MXC_AesSetKey(Aes* aes, byte* userKey, word32 keylen)
{

    return 0;
}
*/

#if defined(MAX3266X_RNG)
/* Use this RNG_FAILURE_E for RNG Errors*/
int wc_MXC_TRNG_Random(byte* output, word32 sz)
{
    /* Obtain Value from TRNG device */
    MXC_TPU_TRNG_Read(MXC_TRNG, output, sz);


    return EXIT_SUCCESS;
}

#endif /* MAX3266x_RNG */

#endif /* WOLFSSL_MAX32665 || WOLFSSL_MAX32666 */