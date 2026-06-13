/* asu_cryptocb.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_VERSAL_GEN2_ASU

#include <wolfssl/wolfcrypt/port/xilinx/versal_gen2_asu/asu_cryptocb.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>

#ifdef WOLFSSL_VERSAL_GEN2_ASU_TRNG
    #include <wolfssl/wolfcrypt/port/xilinx/versal_gen2_asu/asu_rng.h>
#endif

#ifndef WOLF_CRYPTO_CB
    #error "WOLFSSL_VERSAL_GEN2_ASU requires WOLF_CRYPTO_CB"
#endif

/* Crypto callback dispatcher. Each engine handler runs the full operation
 * (looping over ASU transactions as needed) and returns the wolfCrypt result:
 * 0 when the ASU handled it, CRYPTOCB_UNAVAILABLE to fall back to software, or a
 * negative error. Engine cases are filled in per milestone: M1 hash and rng,
 * M2 aes, M3 public key. */
static int wc_AsuCryptoDevCb(int devId, wc_CryptoInfo* info, void* ctx)
{
    int ret = CRYPTOCB_UNAVAILABLE;

    (void)devId;
    (void)ctx;

    if (info == NULL) {
        return BAD_FUNC_ARG;
    }

    switch (info->algo_type) {
        case WC_ALGO_TYPE_HASH:   /* M1 asu_sha  */
            break;
        case WC_ALGO_TYPE_HMAC:   /* M1 asu_hmac */
            break;
        case WC_ALGO_TYPE_SEED:   /* M1 asu_rng  */
        #ifdef WOLFSSL_VERSAL_GEN2_ASU_TRNG
            ret = wc_AsuRngSeed(info);
        #endif
            break;
        case WC_ALGO_TYPE_RNG:    /* M1 asu_rng  */
        #ifdef WOLFSSL_VERSAL_GEN2_ASU_TRNG
            ret = wc_AsuRngGenerate(info);
        #endif
            break;
        case WC_ALGO_TYPE_CIPHER: /* M2 asu_aes  */
            break;
        case WC_ALGO_TYPE_CMAC:   /* M2 asu_aes  */
            break;
        case WC_ALGO_TYPE_PK:     /* M3 asu_rsa and asu_ecc */
            break;
        default:
            break;
    }

    return ret;
}

int wc_AsuCryptoCb_RegisterDevice(int devId)
{
    return wc_CryptoCb_RegisterDevice(devId, wc_AsuCryptoDevCb, NULL);
}

void wc_AsuCryptoCb_UnRegisterDevice(int devId)
{
    wc_CryptoCb_UnRegisterDevice(devId);
}

#endif /* WOLFSSL_VERSAL_GEN2_ASU */
