/* asu_ecdh.h
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

/* ASU ECDH shared-secret offload for the wolfSSL crypto callback. wolfSSL's ECDH
 * callback (wc_ecc_shared_secret) routes here; the ASU computes the X9.63 shared
 * secret (the X coordinate of private_key->k * public_key->pubkey) on the supported
 * NIST/Brainpool prime curves. Keys are marshalled big-endian, fixed-width into the
 * ASU structs; other curves decline to software. See asu_ecdh.c. */

#ifndef WOLFSSL_VERSAL_GEN2_ASU_ECDH_H
#define WOLFSSL_VERSAL_GEN2_ASU_ECDH_H

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_VERSAL_GEN2_ASU_ECDH

#include <wolfssl/wolfcrypt/cryptocb.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Single entry point for the ECDH engine (WC_ALGO_TYPE_PK / WC_PK_TYPE_ECDH).
 * Computes the shared secret on the ASU for the supported curves. Returns 0 on
 * success, CRYPTOCB_UNAVAILABLE to defer to software, or a negative error. */
WOLFSSL_LOCAL int wc_AsuEcdh(wc_CryptoInfo* info);

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_VERSAL_GEN2_ASU_ECDH */

#endif /* WOLFSSL_VERSAL_GEN2_ASU_ECDH_H */
