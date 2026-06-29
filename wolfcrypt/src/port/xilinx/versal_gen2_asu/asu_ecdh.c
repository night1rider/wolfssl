/* asu_ecdh.c
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

/* ASU ECDH offload for the wolfSSL crypto callback.
 *
 * wolfSSL's wc_ecc_shared_secret callback delivers our private key and the peer's
 * public key; the ASU computes the X9.63 shared secret, the X coordinate of
 * private_key->k * public_key->pubkey. The private scalar and the peer point Qx||Qy
 * are marshalled big-endian, fixed-width with mp_to_unsigned_bin_len. The ASU
 * returns the curve-width X coordinate, which matches wolfSSL's fixed-width software
 * output (zero-padded to the curve size). NIST P-192/256/384/521 and Brainpool
 * P-256/320/384/512 prime curves; other curves decline to software.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_VERSAL_GEN2_ASU_ECDH

#include <wolfssl/wolfcrypt/port/xilinx/versal_gen2_asu/asu_ecdh.h>
#include <wolfssl/wolfcrypt/port/xilinx/versal_gen2_asu/asu_util.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/wolfmath.h>

#include "xasu_ecc.h"
#include "xasu_eccinfo.h"
#include "xasu_status.h"
#include "xstatus.h"

#if defined(NO_ECC) || !defined(HAVE_ECC)
    #error "WOLFSSL_VERSAL_GEN2_ASU_ECDH requires ECC"
#endif
#ifndef HAVE_ECC_DHE
    #error "WOLFSSL_VERSAL_GEN2_ASU_ECDH requires HAVE_ECC_DHE"
#endif

/* Largest supported curve width (NIST P-521, 66 bytes). */
#define WC_ASU_ECDH_MAX_KEYLEN  XASU_ECC_P521_SIZE_IN_BYTES

/* One ASU ECDH request: our private scalar, the peer public point, and the
 * resulting shared secret, all heap-resident so the ASU DMA can reach them. */
typedef struct {
    XAsu_EcdhParams params;
    byte privKey[WC_ASU_ECDH_MAX_KEYLEN];      /* our private d */
    byte pubKey[2U * WC_ASU_ECDH_MAX_KEYLEN];  /* peer Qx||Qy */
    byte secret[WC_ASU_ECDH_MAX_KEYLEN];       /* shared secret (X coordinate) */
} AsuEcdhReq;

/* Submit thunk: queue one ASU ECDH shared-secret operation. */
static int wc_AsuEcdhSubmit(XAsu_ClientParams* params, void* ctx)
{
    AsuEcdhReq* req = (AsuEcdhReq*)ctx;

    if (params == NULL || req == NULL) {
        return XST_FAILURE;
    }
    return XAsu_EcdhGenSharedSecret(params, &req->params);
}

/* Map the wolfSSL curve id to an ASU CurveType and byte length for the supported
 * NIST and Brainpool prime curves, declining any other curve so wolfSSL falls back
 * to software. The key's domain size must match the mapped length. */
static int wc_AsuEcdhCurve(ecc_key* key, u32* curveType, u32* keyLen)
{
    u32 type;
    u32 len;

    if (key == NULL || curveType == NULL || keyLen == NULL) {
        return BAD_FUNC_ARG;
    }
    if (key->dp == NULL) {
        return CRYPTOCB_UNAVAILABLE;
    }
    switch (key->dp->id) {
        case ECC_SECP192R1:
            type = (u32)XASU_ECC_NIST_P192;
            len  = (u32)XASU_ECC_P192_SIZE_IN_BYTES;
            break;
        case ECC_SECP256R1:
            type = (u32)XASU_ECC_NIST_P256;
            len  = (u32)XASU_ECC_P256_SIZE_IN_BYTES;
            break;
        case ECC_SECP384R1:
            type = (u32)XASU_ECC_NIST_P384;
            len  = (u32)XASU_ECC_P384_SIZE_IN_BYTES;
            break;
#ifdef WOLFSSL_VERSAL_GEN2_ASU_ECC_P521
        case ECC_SECP521R1:
            type = (u32)XASU_ECC_NIST_P521;
            len  = (u32)XASU_ECC_P521_SIZE_IN_BYTES;
            break;
#endif
#ifdef HAVE_ECC_BRAINPOOL
        case ECC_BRAINPOOLP256R1:
            type = (u32)XASU_ECC_BRAINPOOL_P256;
            len  = (u32)XASU_ECC_P256_SIZE_IN_BYTES;
            break;
        case ECC_BRAINPOOLP320R1:
            type = (u32)XASU_ECC_BRAINPOOL_P320;
            len  = (u32)XASU_ECC_P320_SIZE_IN_BYTES;
            break;
        case ECC_BRAINPOOLP384R1:
            type = (u32)XASU_ECC_BRAINPOOL_P384;
            len  = (u32)XASU_ECC_P384_SIZE_IN_BYTES;
            break;
        case ECC_BRAINPOOLP512R1:
            type = (u32)XASU_ECC_BRAINPOOL_P512;
            len  = (u32)XASU_ECC_P512_SIZE_IN_BYTES;
            break;
#endif
        default:
            return CRYPTOCB_UNAVAILABLE;
    }
    if ((u32)key->dp->size != len) {
        return CRYPTOCB_UNAVAILABLE;
    }
    *curveType = type;
    *keyLen    = len;
    return 0;
}

/* Full-hardware ECDH shared-secret generation. Both keys must be on the same
 * supported curve; the ASU multiplies our private scalar by the peer point and
 * returns the curve-width X coordinate. *outlen is set to the curve width. Any ASU
 * failure defers to software, which is authoritative. */
int wc_AsuEcdh(wc_CryptoInfo* info)
{
    WC_DECLARE_VAR(req, AsuEcdhReq, 1, NULL);
    ecc_key* priv;
    ecc_key* pub;
    u32     curveType = 0;
    u32     keyLen = 0;
    word32  status;
    word32  addl = 0;
    int     ret = 0;

    if (info == NULL) {
        return BAD_FUNC_ARG;
    }
    if (info->algo_type != WC_ALGO_TYPE_PK ||
        info->pk.type != WC_PK_TYPE_ECDH) {
        return CRYPTOCB_UNAVAILABLE;
    }

    priv = info->pk.ecdh.private_key;
    pub  = info->pk.ecdh.public_key;

    if (priv == NULL || pub == NULL || info->pk.ecdh.out == NULL ||
        info->pk.ecdh.outlen == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = wc_AsuEcdhCurve(priv, &curveType, &keyLen);
    if (ret != 0) {
        return ret;
    }
    /* Both keys must be on the same supported curve. */
    if (pub->dp == NULL || pub->dp->id != priv->dp->id) {
        return CRYPTOCB_UNAVAILABLE;
    }
    /* Our private scalar is required and must fit the curve width. */
    if (mp_iszero(priv->k) || mp_unsigned_bin_size(priv->k) > (int)keyLen) {
        return CRYPTOCB_UNAVAILABLE;
    }
    if (*info->pk.ecdh.outlen < keyLen) {
        return CRYPTOCB_UNAVAILABLE;
    }

    WC_ALLOC_VAR_EX(req, AsuEcdhReq, 1, NULL, DYNAMIC_TYPE_TMP_BUFFER,
        ret = MEMORY_E);
    if (!WC_VAR_OK(req)) {
        return ret;
    }

    XMEMSET(req, 0, sizeof(*req));
    /* Our private scalar d, and the peer public point Qx||Qy, each curve-width. */
    if (mp_to_unsigned_bin_len(priv->k, req->privKey, (int)keyLen) < 0 ||
        mp_to_unsigned_bin_len(pub->pubkey.x, req->pubKey, (int)keyLen) < 0 ||
        mp_to_unsigned_bin_len(pub->pubkey.y, req->pubKey + keyLen,
            (int)keyLen) < 0) {
        ret = WC_HW_E;
        goto out;
    }

    req->params.CurveType             = curveType;
    req->params.KeyLen                = keyLen;
    req->params.PvtKeyAddr            = (u64)(UINTPTR)req->privKey;
    req->params.PubKeyAddr            = (u64)(UINTPTR)req->pubKey;
    req->params.SharedSecretAddr      = (u64)(UINTPTR)req->secret;
    req->params.SharedSecretObjIdAddr = 0;

    WC_ASU_PRINTF("[ASU] ecdh curve=%u keyLen=%u\r\n",
        (unsigned int)curveType, (unsigned int)keyLen);

    wc_AsuCacheFlush(req->privKey, keyLen);
    wc_AsuCacheFlush(req->pubKey, 2U * keyLen);

    status = wc_AsuTransact(wc_AsuEcdhSubmit, req, &addl);

    wc_AsuCacheInvalidate(req->secret, keyLen);

    WC_ASU_PRINTF("[ASU] ecdh st=%u addl=0x%x\r\n",
        (unsigned int)status, (unsigned int)addl);

    if (status != XST_SUCCESS) {
        ret = CRYPTOCB_UNAVAILABLE;
        goto out;
    }
    XMEMCPY(info->pk.ecdh.out, req->secret, keyLen);
    *info->pk.ecdh.outlen = keyLen;
    ret = 0;

out:
    WC_FREE_VAR_EX(req, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

#endif /* WOLFSSL_VERSAL_GEN2_ASU_ECDH */
