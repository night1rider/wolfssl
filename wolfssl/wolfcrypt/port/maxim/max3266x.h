/* max3266x.h
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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

#ifndef WOLFSSL_MAX_HASH_SIZE
    #define WOLFSSL_MAX_HASH_SIZE  64
#endif

#if defined(WOLFSSL_MAX3266X) || defined(WOLFSSL_MAX3266X_OLD)

/* Default to all HW acceleration on unless specified in user_settings */
#if !defined(MAX3266X_RNG) && !defined(MAX3266X_AES) && \
        !defined(MAX3266X_AESGCM) && !defined(MAX3266X_SHA) && \
        !defined(MAX3266X_MATH)
    #define MAX3266X_RNG
    #define MAX3266X_AES
    #define MAX3266X_SHA
    #define MAX3266X_ECDSA
    #define MAX3266X_MATH
#endif

#if defined(WOLFSSL_MAX3266X_OLD)
    /* Support for older SDK API Maxim provides */

    /* These are needed for older SDK */
    #define TARGET MAX32665
    #define TARGET_REV 0x4131
    #include "mxc_sys.h"



    #if defined(MAX3266X_RNG)
        #include "trng.h"   /* Provides TRNG Drivers */
        #define MXC_TPU_TRNG_Read       TRNG_Read
    #endif
    #if defined(MAX3266X_AES)
        #include "cipher.h" /* Provides Drivers for AES */
        /* AES Defines */
        #define MXC_TPU_CIPHER_TYPE      tpu_ciphersel_t
        #define MXC_TPU_CIPHER_AES128    TPU_CIPHER_AES128
        #define MXC_TPU_CIPHER_AES192    TPU_CIPHER_AES192
        #define MXC_TPU_CIPHER_AES256    TPU_CIPHER_AES256

        #define MXC_TPU_MODE_TYPE        tpu_modesel_t
        #define MXC_TPU_MODE_ECB         TPU_MODE_ECB
        #define MXC_TPU_MODE_CBC         TPU_MODE_CBC
        #define MXC_TPU_MODE_CFB         TPU_MODE_CFB
        #define MXC_TPU_MODE_CTR         TPU_MODE_CTR

        /* AES Functions */
        #define MXC_TPU_Cipher_Config       TPU_Cipher_Config
        #define MXC_TPU_Cipher_AES_Encrypt  TPU_AES_Encrypt
        #define MXC_TPU_Cipher_AES_Decrypt  TPU_AES_Decrypt

    #endif
    #if defined(MAX3266X_SHA)
        #include "hash.h"   /* Proivdes Drivers for SHA */
        /* SHA Defines */
        #define MXC_TPU_HASH_TYPE        tpu_hashfunsel_t
        #define MXC_TPU_HASH_SHA1        TPU_HASH_SHA1
        #define MXC_TPU_HASH_SHA224      TPU_HASH_SHA224
        #define MXC_TPU_HASH_SHA256      TPU_HASH_SHA256
        #define MXC_TPU_HASH_SHA384      TPU_HASH_SHA384
        #define MXC_TPU_HASH_SHA512      TPU_HASH_SHA512

        /* SHA Functions */
        #define MXC_TPU_Hash_Config             TPU_Hash_Config
        #define MXC_TPU_Hash_SHA                TPU_SHA

    #endif
    #if defined(MAX3266X_MATH)
        #include "maa.h"    /* Provides Drivers for math acceleration for   */
                            /* ECDSA and RSA Acceleration                   */
        /* MAA Defines */
        #define MXC_TPU_MAA_TYPE     tpu_maa_clcsel_t
        #define WC_MXC_TPU_MAA_EXP      0b0000
        #define WC_MXC_TPU_MAA_SQ       0b0010
        #define WC_MXC_TPU_MAA_MUL      0b0100
        #define WC_MXC_TPU_MAA_SQMUL    0b0110
        #define WC_MXC_TPU_MAA_ADD      0b1000
        #define WC_MXC_TPU_MAA_SUB      0b1010

        /* MAA Functions */
        #define MXC_TPU_MAA_Compute      MAA_Compute
        #define MXC_TPU_MAA_Shutdown     MAA_Shutdown
        #define MXC_TPU_MAA_Init         MAA_Init
        #define MXC_TPU_MAA_Reset        MAA_Reset

    #endif

    /* TPU Functions */
    #define MXC_TPU_Init                SYS_TPU_Init
    #define MXC_TPU_Shutdown            SYS_TPU_Shutdown
    #define MXC_SYS_PERIPH_CLOCK_TPU    SYS_PERIPH_CLOCK_TPU

    #define MXC_SYS_PERIPH_CLOCK_TPU    SYS_PERIPH_CLOCK_TPU
    #define MXC_SYS_PERIPH_CLOCK_TRNG   SYS_PERIPH_CLOCK_TRNG

#else
    /* Defaults to expect newer SDK */
    #if defined(MAX3266X_RNG)
        #include "trng.h"   /* Provides Drivers for TRNG    */
    #endif
    #if defined(MAX3266X_AES) || defined(MAX3266X_SHA) || \
                defined(MAX3266X_ECDSA) || defined(MAX3266X_RSA) || \
                defined(MAX3266X_RNG)
        #include "tpu.h"    /* SDK Drivers for the TPU unit         */
                            /* Handles AES, SHA, and                */
                            /* MAA driver to accelerate RSA/ECDSA   */

        /* AES Defines */
        #define MXC_TPU_CIPHER_TYPE     mxc_tpu_ciphersel_t
        #define MXC_TPU_MODE_TYPE       mxc_tpu_modesel_t


        /* SHA Defines */
        #define MXC_TPU_HASH_TYPE       mxc_tpu_hashfunsel_t


        /* MAA Defines */
        /* Current SDK for TPU does not handle bit mask correctly */
        /* with expected enum values, so calue need to be set */
        /* manually to work with intended naming scheme */
        #define MXC_TPU_MAA_TYPE     mxc_tpu_maa_clcsel_t
        #define WC_MXC_TPU_MAA_EXP      0b0000
        #define WC_MXC_TPU_MAA_SQ       0b0010
        #define WC_MXC_TPU_MAA_MUL      0b0100
        #define WC_MXC_TPU_MAA_SQMUL    0b0110
        #define WC_MXC_TPU_MAA_ADD      0b1000
        #define WC_MXC_TPU_MAA_SUB      0b1010

    #endif

#endif


/* Provide Driver for RTC if specified, meant for wolfCrypt benchmark only */
#if defined(MAX3266X_RTC)
    #if defined(WOLFSSL_MAX3266X_OLD)
       #error Not Implemented with old SDK
    #endif
    #include "time.h"
    #include "rtc.h"
    #define MXC_SECS_PER_MIN (60)
    #define MXC_SECS_PER_HR  (60 * MXC_SECS_PER_MIN)
    #define MXC_SECS_PER_DAY (24 * MXC_SECS_PER_HR)
#endif

/* Variable Definitions */
#ifdef __cplusplus
    extern "C" {
#endif

    WOLFSSL_LOCAL int wc_MXC_TPU_Init(void);
    WOLFSSL_LOCAL int wc_MXC_TPU_Shutdown(void);
    /* Convert Errors to wolfCrypt Codes */
    WOLFSSL_LOCAL int wc_MXC_error(int *ret);

#ifdef MAX3266X_RTC
    WOLFSSL_LOCAL int wc_MXC_RTC_Init(void);
    WOLFSSL_LOCAL int wc_MXC_RTC_Reset(void);
    WOLFSSL_LOCAL double wc_MXC_RTC_Time(void);
#endif


#ifdef MAX3266X_RNG
    WOLFSSL_LOCAL int wc_MXC_TRNG_Random(unsigned char* output,
                                                unsigned int sz);
#endif

#ifdef MAX3266X_AES
    WOLFSSL_LOCAL int wc_MXC_TPU_AesEncrypt(const char *in, const char *iv,
                                const char *enc_key,
                                MXC_TPU_MODE_TYPE mode,
                                unsigned int data_size,
                                char *out, unsigned int keySize);

    WOLFSSL_LOCAL int wc_MXC_TPU_AesDecrypt(const char *in, const char *iv,
                                const char *enc_key,
                                MXC_TPU_MODE_TYPE mode,
                                unsigned int data_size,
                                char *out, unsigned int keySize);
#endif

#ifdef MAX3266X_SHA

    typedef struct {
        unsigned char   *msg;
        unsigned int    used;
        unsigned int    size;
        unsigned char   hash[WOLFSSL_MAX_HASH_SIZE];
    } wc_MXC_Sha;

    #if !defined(NO_SHA256)
        typedef wc_MXC_Sha wc_Sha256;
        #define WC_SHA256_TYPE_DEFINED

        /* Define the SHA-256 digest for an empty string */
        /* as a constant byte array */
        static const unsigned char MXC_EMPTY_DIGEST_SHA256[32] = {
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
                0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
                0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
                0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};

    #endif


    WOLFSSL_LOCAL int wc_MXC_TPU_SHA_Init(wc_MXC_Sha *hash);
    WOLFSSL_LOCAL int wc_MXC_TPU_SHA_Update(wc_MXC_Sha *hash,
                                                const unsigned char* data,
                                                unsigned int size);
    WOLFSSL_LOCAL int wc_MXC_TPU_SHA_Final(wc_MXC_Sha *hash,
                                                unsigned char* digest,
                                                MXC_TPU_HASH_TYPE algo);
    WOLFSSL_LOCAL int wc_MXC_TPU_SHA_GetHash(wc_MXC_Sha *hash,
                                                unsigned char* digest,
                                                MXC_TPU_HASH_TYPE algo);
    WOLFSSL_LOCAL int wc_MXC_TPU_SHA_Copy(wc_MXC_Sha* src, wc_MXC_Sha* dst);
    WOLFSSL_LOCAL void wc_MXC_TPU_SHA_Free(wc_MXC_Sha* hash);
    WOLFSSL_LOCAL int wc_MXC_TPU_SHA_GetDigest(wc_MXC_Sha *hash,
                                                unsigned char* digest,
                                                MXC_TPU_HASH_TYPE algo);


#endif

#if defined(MAX3266X_MATH)
    #define WOLFSSL_USE_HW_MP
    /* Setup mapping to fallback if edge case is encountered */
    #if defined(USE_FAST_MATH)
        #define mxc_mod         fp_mod
        #define mxc_addmod      fp_addmod
        #define mxc_submod      fp_submod
        #define mxc_mulmod      fp_mulmod
        #define mxc_exptmod     fp_exptmod
        #define mxc_sqrmod      fp_sqrmod
    #elif defined(WOLFSSL_SP_MATH_ALL)
        #define mxc_mod         sp_mod
        #define mxc_addmod      sp_addmod
        #define mxc_submod      sp_submod
        #define mxc_mulmod      sp_mulmod
        #define mxc_exptmod     sp_exptmod
        #define mxc_sqrmod      sp_sqrmod
    #else
        #error Need to use WOLFSSL_SP_MATH_ALL
    #endif

#endif

#ifdef __cplusplus
    }
#endif

#endif /* WOLFSSL_MAX32665 || WOLFSSL_MAX32666 */
#endif /* _WOLFPORT_MAX3266X_H_ */