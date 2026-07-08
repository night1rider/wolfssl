/* asu_ecies.c
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

/* ASU ECIES offload for the wolfSSL crypto callback.
 *
 * wolfSSL's ECIES with the AES-GCM DEM is: ECDH -> HKDF(shared secret, salt, info)
 * -> one AES key -> AES-GCM (fresh 12-byte nonce, 16-byte tag), output packed as
 * [ephemeral pubkey (X9.63 uncompressed) || nonce || ciphertext || tag]. The ASU
 * XEcies engine performs exactly this in one command, so the offload marshals the
 * keys and scheme parameters, runs XAsu_EciesEncrypt/Decrypt, and reassembles the
 * output in wolfSSL's layout.
 *
 * The ASU always generates its own ephemeral keypair on encrypt (wolfSSL's supplied
 * ephemeral private key is unused); the ASU's ephemeral public key is emitted in the
 * output and the peer decrypts against it, so the result is self-consistent. Only the
 * default GCM scheme (AES-128/256-GCM + HKDF-SHA256, shared-secret-only, uncompressed
 * ephemeral key) is offloaded; anything else declines to software.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_VERSAL_GEN2_ASU_ECIES

#include <wolfssl/wolfcrypt/port/xilinx/versal_gen2_asu/asu_ecies.h>
#include <wolfssl/wolfcrypt/port/xilinx/versal_gen2_asu/asu_util.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/wolfmath.h>
#include <wolfssl/wolfcrypt/random.h>

#include "xasu_ecies.h"
#include "xasu_eciesinfo.h"
#include "xasu_eccinfo.h"
#include "xasu_shainfo.h"
#include "xasu_aesinfo.h"
#include "xstatus.h"

#if defined(NO_ECC) || !defined(HAVE_ECC)
    #error "WOLFSSL_VERSAL_GEN2_ASU_ECIES requires ECC"
#endif
#ifndef HAVE_ECC_ENCRYPT
    #error "WOLFSSL_VERSAL_GEN2_ASU_ECIES requires HAVE_ECC_ENCRYPT"
#endif
#if defined(NO_AES) || !defined(HAVE_AESGCM)
    #error "WOLFSSL_VERSAL_GEN2_ASU_ECIES requires AES-GCM"
#endif

/* wolfSSL ecEncAlgo AES-GCM values and the ECIES DEM sizes. */
#define WC_ASU_ECIES_AES128_GCM   5
#define WC_ASU_ECIES_AES256_GCM   6
#define WC_ASU_ECIES_HKDF_SHA256  1   /* wolfSSL ecKdfAlgo default */
#define WC_ASU_ECIES_NONCE_SZ     12
#define WC_ASU_ECIES_TAG_SZ       16

/* Largest supported curve width (NIST P-384, 48 bytes; P-521 is not offloaded). */
#define WC_ASU_ECIES_MAX_KEYLEN   XASU_ECC_P384_SIZE_IN_BYTES

/* One ASU ECIES request. The plaintext/ciphertext live in the caller's buffers
 * (variable length, addressed directly); the fixed-size key/nonce/tag records are
 * heap-resident here so the ASU DMA can reach them. */
typedef struct {
    XAsu_EciesParams params;
    byte rxKey[2U * WC_ASU_ECIES_MAX_KEYLEN];  /* peer pub Qx||Qy (enc) or priv d (dec) */
    byte txKey[2U * WC_ASU_ECIES_MAX_KEYLEN];  /* ephemeral pub Qx||Qy (enc out/dec in) */
    byte iv[WC_ASU_ECIES_NONCE_SZ];            /* GCM nonce */
    byte tag[WC_ASU_ECIES_TAG_SZ];             /* GCM tag */
} AsuEciesReq;

/* Submit thunk: queue one ASU ECIES operation. IsEncrypt picks the command. */
typedef struct {
    AsuEciesReq* req;
    int          isEncrypt;
} AsuEciesSubmitCtx;

static int wc_AsuEciesSubmit(XAsu_ClientParams* params, void* ctx)
{
    AsuEciesSubmitCtx* sc = (AsuEciesSubmitCtx*)ctx;

    if (params == NULL || sc == NULL || sc->req == NULL) {
        return XST_FAILURE;
    }
    if (sc->isEncrypt != 0) {
        return XAsu_EciesEncrypt(params, &sc->req->params);
    }
    return XAsu_EciesDecrypt(params, &sc->req->params);
}

/* Map the wolfSSL curve id to an ASU CurveType and byte width for the ECIES-capable
 * prime curves, declining others so wolfSSL falls back to software. */
static int wc_AsuEciesCurve(ecc_key* key, u8* curveType, u8* keyLen)
{
    if (key == NULL || curveType == NULL || keyLen == NULL) {
        return BAD_FUNC_ARG;
    }
    if (key->dp == NULL) {
        return CRYPTOCB_UNAVAILABLE;
    }
    switch (key->dp->id) {
        case ECC_SECP256R1:
            *curveType = (u8)XASU_ECC_NIST_P256;
            *keyLen    = (u8)XASU_ECC_P256_SIZE_IN_BYTES;
            break;
        case ECC_SECP384R1:
            *curveType = (u8)XASU_ECC_NIST_P384;
            *keyLen    = (u8)XASU_ECC_P384_SIZE_IN_BYTES;
            break;
#ifdef HAVE_ECC_BRAINPOOL
        case ECC_BRAINPOOLP256R1:
            *curveType = (u8)XASU_ECC_BRAINPOOL_P256;
            *keyLen    = (u8)XASU_ECC_P256_SIZE_IN_BYTES;
            break;
        case ECC_BRAINPOOLP384R1:
            *curveType = (u8)XASU_ECC_BRAINPOOL_P384;
            *keyLen    = (u8)XASU_ECC_P384_SIZE_IN_BYTES;
            break;
#endif
        default:
            return CRYPTOCB_UNAVAILABLE;
    }
    return 0;
}

/* Read the ECIES scheme from the ctx. Only AES-128/256-GCM with HKDF-SHA256 is
 * offloaded; anything else declines. Fills the ASU AES key size and SHA type/mode. */
static int wc_AsuEciesScheme(ecEncCtx* ctx, u8* aesKeySize, u8* shaType, u8* shaMode)
{
    byte encAlgo = 0;
    byte kdfAlgo = 0;

    if (ctx == NULL || aesKeySize == NULL || shaType == NULL || shaMode == NULL) {
        return BAD_FUNC_ARG;
    }
    if (wc_ecc_ctx_get_algo(ctx, &encAlgo, &kdfAlgo, NULL) != 0) {
        return CRYPTOCB_UNAVAILABLE;
    }
    if (kdfAlgo != WC_ASU_ECIES_HKDF_SHA256) {
        return CRYPTOCB_UNAVAILABLE;
    }
    if (encAlgo == WC_ASU_ECIES_AES128_GCM) {
        *aesKeySize = (u8)XASU_AES_KEY_SIZE_128_BITS;
    }
    else if (encAlgo == WC_ASU_ECIES_AES256_GCM) {
        *aesKeySize = (u8)XASU_AES_KEY_SIZE_256_BITS;
    }
    else {
        return CRYPTOCB_UNAVAILABLE;
    }
    *shaType = (u8)XASU_SHA2_TYPE;
    *shaMode = (u8)XASU_SHA_MODE_256;
    return 0;
}

/* Marshal an ecc_key public point into Qx||Qy, big-endian fixed width. */
static int wc_AsuEciesExportPub(ecc_key* key, byte* out, u8 keyLen)
{
    if (mp_to_unsigned_bin_len(key->pubkey.x, out, (int)keyLen) < 0) {
        return WC_HW_E;
    }
    if (mp_to_unsigned_bin_len(key->pubkey.y, out + keyLen, (int)keyLen) < 0) {
        return WC_HW_E;
    }
    return 0;
}

/* Fill the common ECIES params (scheme, salt/info, lengths) shared by enc/dec. */
static void wc_AsuEciesFillParams(XAsu_EciesParams* p, ecEncCtx* ctx, u8 curveType,
    u8 keyLen, u8 aesKeySize, u8 shaType, u8 shaMode, word32 dataLen)
{
    word32      saltLen = 0;
    word32      infoLen = 0;
    const byte* salt = wc_ecc_ctx_get_kdf_salt(ctx, &saltLen);
    const byte* info = wc_ecc_ctx_get_kdf_info(ctx, &infoLen);

    p->EccCurveType = curveType;
    p->EccKeyLength = keyLen;
    p->ShaType      = shaType;
    p->ShaMode      = shaMode;
    p->AesKeySize   = aesKeySize;
    p->IvLength     = (u8)WC_ASU_ECIES_NONCE_SZ;
    p->MacLength    = (u8)WC_ASU_ECIES_TAG_SZ;
    p->DataLength   = dataLen;
    p->SaltAddr     = (u64)(UINTPTR)salt;
    p->SaltLen      = saltLen;
    p->ContextAddr  = (u64)(UINTPTR)info;
    p->ContextLen   = infoLen;
}

/* ECIES encrypt: peer public key + plaintext -> [ephemeral||nonce||ct||tag]. The
 * ASU generates the ephemeral keypair, derives the key, and GCM-encrypts. */
static int wc_AsuEciesEncrypt(wc_CryptoInfo* info)
{
    WC_DECLARE_VAR(req, AsuEciesReq, 1, NULL);
    AsuEciesSubmitCtx sc;
    ecc_key* privKey = info->pk.eciesencrypt.privKey;   /* ephemeral, carries the RNG */
    ecc_key* pubKey = info->pk.eciesencrypt.pubKey;
    const byte* msg = info->pk.eciesencrypt.msg;
    word32   msgSz  = info->pk.eciesencrypt.msgSz;
    byte*    out    = info->pk.eciesencrypt.out;
    ecEncCtx* ctx   = info->pk.eciesencrypt.ctx;
    WC_RNG*  rng    = NULL;
    u8       curveType = 0;
    u8       keyLen = 0;
    u8       aesKeySize = 0;
    u8       shaType = 0;
    u8       shaMode = 0;
    word32   pubKeySz;
    word32   need;
    word32   status;
    word32   addl = 0;
    int      ret;

    /* Decline (fall back to software) for anything not fully handled; a hard error
     * from the callback would abort the op instead of falling back. */
    if (pubKey == NULL || msg == NULL || out == NULL ||
        info->pk.eciesencrypt.outSz == NULL || ctx == NULL) {
        return CRYPTOCB_UNAVAILABLE;
    }
    /* The ASU emits an uncompressed ephemeral key; decline a compressed request. */
    if (info->pk.eciesencrypt.compressed != 0) {
        return CRYPTOCB_UNAVAILABLE;
    }
    ret = wc_AsuEciesCurve(pubKey, &curveType, &keyLen);
    if (ret != 0) {
        return ret;
    }
    ret = wc_AsuEciesScheme(ctx, &aesKeySize, &shaType, &shaMode);
    if (ret != 0) {
        return ret;
    }
    /* Only GCM reaches here (other schemes already declined to software).
     * AAD: REQ_RESP binds macSalt as GCM AAD, which the ASU has no input for. This
     * is a legitimate wolfSSL scheme (wolfcrypt's own tests use it), so decline and
     * let software handle it. Context: the caller opted into HW GCM without an AAD
     * but left the KDF context empty, which the ASU firmware requires; that is a
     * usage error for the HW path, so reject it with BAD_FUNC_ARG. */
    {
        word32 macSaltSz = 0;
        word32 infoSz    = 0;
        (void)wc_ecc_ctx_get_mac_salt(ctx, &macSaltSz);
        (void)wc_ecc_ctx_get_kdf_info(ctx, &infoSz);
        if (macSaltSz > 0U) {
            return CRYPTOCB_UNAVAILABLE;
        }
        if (infoSz == 0U) {
            WC_ASU_PRINTF("[ASU] ecies: GCM needs a non-empty KDF context\r\n");
            return BAD_FUNC_ARG;
        }
    }
    /* A random nonce is needed; the ephemeral key carries the RNG. Decline if none. */
    if (privKey == NULL) {
        return CRYPTOCB_UNAVAILABLE;
    }
    rng = privKey->rng;
    if (rng == NULL) {
        return CRYPTOCB_UNAVAILABLE;
    }

    pubKeySz = 1U + (2U * (word32)keyLen);   /* X9.63 uncompressed 0x04||Qx||Qy */
    need = pubKeySz + (word32)WC_ASU_ECIES_NONCE_SZ + msgSz +
           (word32)WC_ASU_ECIES_TAG_SZ;
    if (*info->pk.eciesencrypt.outSz < need) {
        return BUFFER_E;
    }

    WC_ALLOC_VAR_EX(req, AsuEciesReq, 1, NULL, DYNAMIC_TYPE_TMP_BUFFER,
        ret = MEMORY_E);
    if (!WC_VAR_OK(req)) {
        return ret;
    }
    XMEMSET(req, 0, sizeof(*req));

    ret = wc_AsuEciesExportPub(pubKey, req->rxKey, keyLen);
    if (ret != 0) {
        goto out;
    }
    ret = wc_RNG_GenerateBlock(rng, req->iv, WC_ASU_ECIES_NONCE_SZ);
    if (ret != 0) {
        goto out;
    }

    wc_AsuEciesFillParams(&req->params, ctx, curveType, keyLen, aesKeySize,
        shaType, shaMode, msgSz);
    req->params.RxKeyAddr  = (u64)(UINTPTR)req->rxKey;   /* peer public key in */
    req->params.TxKeyAddr  = (u64)(UINTPTR)req->txKey;   /* ephemeral public key out */
    req->params.IvAddr     = (u64)(UINTPTR)req->iv;
    req->params.MacAddr    = (u64)(UINTPTR)req->tag;     /* GCM tag out */
    req->params.InDataAddr = (u64)(UINTPTR)msg;          /* plaintext in */
    req->params.OutDataAddr = (u64)(UINTPTR)(out + pubKeySz +
        (word32)WC_ASU_ECIES_NONCE_SZ);                  /* ciphertext out, in place */

    WC_ASU_PRINTF("[ASU] ecies enc curve=%u keyLen=%u aesKey=%u msgSz=%u\r\n",
        (unsigned int)curveType, (unsigned int)keyLen, (unsigned int)aesKeySize,
        (unsigned int)msgSz);

    /* Clean inputs out to memory; invalidate the DMA-written regions after. */
    wc_AsuCacheFlush(req, sizeof(*req));
    wc_AsuCacheFlush(msg, msgSz);
    if (req->params.SaltLen != 0) {
        wc_AsuCacheFlush((const void*)(UINTPTR)req->params.SaltAddr,
            req->params.SaltLen);
    }
    if (req->params.ContextLen != 0) {
        wc_AsuCacheFlush((const void*)(UINTPTR)req->params.ContextAddr,
            req->params.ContextLen);
    }
    wc_AsuCacheFlush(out, need);

    sc.req = req;
    sc.isEncrypt = 1;
    status = wc_AsuTransact(wc_AsuEciesSubmit, &sc, &addl);

    wc_AsuCacheInvalidate(req, sizeof(*req));
    wc_AsuCacheInvalidate(out, need);

    if (status != XST_SUCCESS) {
        ret = WC_HW_E;
        goto out;
    }

    /* Assemble wolfSSL's layout: 0x04 || ephemeral Qx||Qy || nonce || ct || tag.
     * The ciphertext is already in place; place the ephemeral key, nonce, tag. */
    out[0] = (byte)ECC_POINT_UNCOMP;
    XMEMCPY(out + 1, req->txKey, 2U * (word32)keyLen);
    XMEMCPY(out + pubKeySz, req->iv, WC_ASU_ECIES_NONCE_SZ);
    XMEMCPY(out + pubKeySz + (word32)WC_ASU_ECIES_NONCE_SZ + msgSz, req->tag,
        WC_ASU_ECIES_TAG_SZ);
    *info->pk.eciesencrypt.outSz = need;
    ret = 0;

out:
    WC_FREE_VAR_EX(req, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

/* ECIES decrypt: [ephemeral||nonce||ct||tag] + own private key -> plaintext. The
 * ASU derives the key from ECDH(own priv, ephemeral pub) and GCM-decrypts/verifies. */
static int wc_AsuEciesDecrypt(wc_CryptoInfo* info)
{
    WC_DECLARE_VAR(req, AsuEciesReq, 1, NULL);
    AsuEciesSubmitCtx sc;
    ecc_key* privKey = info->pk.eciesdecrypt.privKey;
    const byte* msg  = info->pk.eciesdecrypt.msg;
    word32   msgSz   = info->pk.eciesdecrypt.msgSz;
    byte*    out     = info->pk.eciesdecrypt.out;
    ecEncCtx* ctx    = info->pk.eciesdecrypt.ctx;
    u8       curveType = 0;
    u8       keyLen = 0;
    u8       aesKeySize = 0;
    u8       shaType = 0;
    u8       shaMode = 0;
    word32   pubKeySz;
    word32   ctLen;
    word32   status;
    word32   addl = 0;
    int      ret;

    /* Decline (fall back to software) for anything not fully handled. */
    if (privKey == NULL || msg == NULL || out == NULL ||
        info->pk.eciesdecrypt.outSz == NULL || ctx == NULL) {
        return CRYPTOCB_UNAVAILABLE;
    }
    if (mp_iszero(privKey->k) == MP_YES) {
        return CRYPTOCB_UNAVAILABLE;
    }
    ret = wc_AsuEciesCurve(privKey, &curveType, &keyLen);
    if (ret != 0) {
        return ret;
    }
    ret = wc_AsuEciesScheme(ctx, &aesKeySize, &shaType, &shaMode);
    if (ret != 0) {
        return ret;
    }
    /* Only GCM reaches here (other schemes already declined to software).
     * AAD: REQ_RESP binds macSalt as GCM AAD, which the ASU has no input for. This
     * is a legitimate wolfSSL scheme (wolfcrypt's own tests use it), so decline and
     * let software handle it. Context: the caller opted into HW GCM without an AAD
     * but left the KDF context empty, which the ASU firmware requires; that is a
     * usage error for the HW path, so reject it with BAD_FUNC_ARG. */
    {
        word32 macSaltSz = 0;
        word32 infoSz    = 0;
        (void)wc_ecc_ctx_get_mac_salt(ctx, &macSaltSz);
        (void)wc_ecc_ctx_get_kdf_info(ctx, &infoSz);
        if (macSaltSz > 0U) {
            return CRYPTOCB_UNAVAILABLE;
        }
        if (infoSz == 0U) {
            WC_ASU_PRINTF("[ASU] ecies: GCM needs a non-empty KDF context\r\n");
            return BAD_FUNC_ARG;
        }
    }

    /* The ephemeral key is uncompressed X9.63; decline compressed. */
    if (msgSz < 1U || msg[0] != (byte)ECC_POINT_UNCOMP) {
        return CRYPTOCB_UNAVAILABLE;
    }
    pubKeySz = 1U + (2U * (word32)keyLen);
    if (msgSz < pubKeySz + (word32)WC_ASU_ECIES_NONCE_SZ +
        (word32)WC_ASU_ECIES_TAG_SZ) {
        return BAD_FUNC_ARG;
    }
    ctLen = msgSz - pubKeySz - (word32)WC_ASU_ECIES_NONCE_SZ -
        (word32)WC_ASU_ECIES_TAG_SZ;
    if (*info->pk.eciesdecrypt.outSz < ctLen) {
        return BUFFER_E;
    }

    WC_ALLOC_VAR_EX(req, AsuEciesReq, 1, NULL, DYNAMIC_TYPE_TMP_BUFFER,
        ret = MEMORY_E);
    if (!WC_VAR_OK(req)) {
        return ret;
    }
    XMEMSET(req, 0, sizeof(*req));

    /* Our private scalar; the ephemeral public key comes straight from the blob. */
    if (mp_to_unsigned_bin_len(privKey->k, req->rxKey, (int)keyLen) < 0) {
        ret = WC_HW_E;
        goto out;
    }
    XMEMCPY(req->txKey, msg + 1, 2U * (word32)keyLen);
    XMEMCPY(req->iv, msg + pubKeySz, WC_ASU_ECIES_NONCE_SZ);
    XMEMCPY(req->tag, msg + msgSz - (word32)WC_ASU_ECIES_TAG_SZ,
        WC_ASU_ECIES_TAG_SZ);

    wc_AsuEciesFillParams(&req->params, ctx, curveType, keyLen, aesKeySize,
        shaType, shaMode, ctLen);
    req->params.RxKeyAddr  = (u64)(UINTPTR)req->rxKey;   /* our private key in */
    req->params.TxKeyAddr  = (u64)(UINTPTR)req->txKey;   /* ephemeral public key in */
    req->params.IvAddr     = (u64)(UINTPTR)req->iv;
    req->params.MacAddr    = (u64)(UINTPTR)req->tag;     /* GCM tag in */
    req->params.InDataAddr = (u64)(UINTPTR)(msg + pubKeySz +
        (word32)WC_ASU_ECIES_NONCE_SZ);                  /* ciphertext in */
    req->params.OutDataAddr = (u64)(UINTPTR)out;         /* plaintext out */

    WC_ASU_PRINTF("[ASU] ecies dec curve=%u keyLen=%u aesKey=%u ctLen=%u\r\n",
        (unsigned int)curveType, (unsigned int)keyLen, (unsigned int)aesKeySize,
        (unsigned int)ctLen);

    wc_AsuCacheFlush(req, sizeof(*req));
    wc_AsuCacheFlush(msg, msgSz);
    if (req->params.SaltLen != 0) {
        wc_AsuCacheFlush((const void*)(UINTPTR)req->params.SaltAddr,
            req->params.SaltLen);
    }
    if (req->params.ContextLen != 0) {
        wc_AsuCacheFlush((const void*)(UINTPTR)req->params.ContextAddr,
            req->params.ContextLen);
    }
    wc_AsuCacheFlush(out, ctLen);

    sc.req = req;
    sc.isEncrypt = 0;
    status = wc_AsuTransact(wc_AsuEciesSubmit, &sc, &addl);

    wc_AsuCacheInvalidate(out, ctLen);

    if (status != XST_SUCCESS) {
        ret = WC_HW_E;
        goto out;
    }
    *info->pk.eciesdecrypt.outSz = ctLen;
    ret = 0;

out:
    WC_FREE_VAR_EX(req, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

/* Single entry point for the ECIES engine, reached from the PK dispatcher. */
int wc_AsuEcies(wc_CryptoInfo* info)
{
    if (info == NULL) {
        return BAD_FUNC_ARG;
    }
    if (info->pk.type == WC_PK_TYPE_ECIES_ENCRYPT) {
        return wc_AsuEciesEncrypt(info);
    }
    if (info->pk.type == WC_PK_TYPE_ECIES_DECRYPT) {
        return wc_AsuEciesDecrypt(info);
    }
    return CRYPTOCB_UNAVAILABLE;
}

#endif /* WOLFSSL_VERSAL_GEN2_ASU_ECIES */
