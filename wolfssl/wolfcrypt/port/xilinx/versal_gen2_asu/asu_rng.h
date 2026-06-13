/* asu_rng.h
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

/* ASU TRNG entropy for the wolfSSL crypto callback. Seeds the wolfCrypt Hash
 * DRBG from the ASU true random number generator. */

#ifndef WOLFSSL_VERSAL_GEN2_ASU_RNG_H
#define WOLFSSL_VERSAL_GEN2_ASU_RNG_H

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_VERSAL_GEN2_ASU_TRNG

#include <wolfssl/wolfcrypt/cryptocb.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Fill the wolfSSL seed buffer (info->seed) with entropy from the ASU TRNG for
 * WC_ALGO_TYPE_SEED, providing the TRNG as a seed source for the DRBG. The ASU
 * TRNG returns at most one strength block (32 bytes) per call, so larger
 * requests are filled over several ASU transactions. Returns 0 on success or a
 * negative error. */
WOLFSSL_LOCAL int wc_AsuRngSeed(wc_CryptoInfo* info);

/* Fill the wolfSSL rng output buffer (info->rng) with random bytes straight
 * from the ASU TRNG for WC_ALGO_TYPE_RNG, chunked the same way. Returns 0 on
 * success or a negative error. */
WOLFSSL_LOCAL int wc_AsuRngGenerate(wc_CryptoInfo* info);

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_VERSAL_GEN2_ASU_TRNG */

#endif /* WOLFSSL_VERSAL_GEN2_ASU_RNG_H */
