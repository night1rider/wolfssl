/* asu_cipher.c
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

/* ASU symmetric cipher engine for the wolfSSL crypto callback: AES-CBC and
 * AES-ECB offload. Each call is one atomic ASU operation; the raw key
 * (aes->devKey) and CBC chaining IV (aes->reg) live on the wolfSSL Aes context,
 * so no per-context state is kept here and no copy/free handlers are needed. The
 * ASU supports only 128 and 256 bit keys and whole 16 byte blocks; AES-192,
 * partial blocks and every other mode are declined to software. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_VERSAL_GEN2_ASU_CIPHER

#include <wolfssl/wolfcrypt/port/xilinx/versal_gen2_asu/asu_cipher.h>
#include <wolfssl/wolfcrypt/port/xilinx/versal_gen2_asu/asu_util.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/aes.h>

#include "xasu_aes.h"
#include "xasu_aesinfo.h"
#include "xasu_def.h"
#include "xasu_status.h"
#include "xstatus.h"

/* One ASU AES request: the params block and the key object it points at. */
typedef struct {
    XAsu_AesParams    params;
    XAsu_AesKeyObject keyObj;
} AsuCipherReq;

/* Submit thunk: queue one ASU AES operation. Called by wc_AsuTransact with the
 * submit lock held, so it only queues the request. */
static int wc_AsuCipherSubmit(XAsu_ClientParams* params, void* ctx)
{
    AsuCipherReq* req = (AsuCipherReq*)ctx;

    if (params == NULL || req == NULL) {
        return XST_FAILURE;
    }

    return XAsu_AesOperation(params, &req->params);
}

/* Map a wolfSSL key length to the ASU key size. Returns CRYPTOCB_UNAVAILABLE for
 * AES-192 and any other unsupported length so wolfSSL falls back to software. */
static int wc_AsuCipherKeySize(word32 keyLen, u32* keySize)
{
    if (keySize == NULL) {
        return BAD_FUNC_ARG;
    }
    if (keyLen == XASU_AES_KEY_SIZE_128BIT_IN_BYTES) {
        *keySize = XASU_AES_KEY_SIZE_128_BITS;
        return 0;
    }
    if (keyLen == XASU_AES_KEY_SIZE_256BIT_IN_BYTES) {
        *keySize = XASU_AES_KEY_SIZE_256_BITS;
        return 0;
    }

    return CRYPTOCB_UNAVAILABLE;
}

/* Run one AES operation on the ASU. iv is NULL for ECB. Declines (software
 * fallback) for null/empty input, non block aligned size, or unsupported key. */
static int wc_AsuCipherOneShot(Aes* aes, byte* out, const byte* in, word32 sz,
    int enc, u8 engineMode, const byte* iv)
{
    AsuCipherReq req;
    u32          keySize = 0;
    word32       status;
    int          ret;

    if (aes == NULL || out == NULL || in == NULL) {
        return BAD_FUNC_ARG;
    }
    /* The ASU client accepts only whole 16-byte blocks within the DMA limit;
     * non block-aligned or oversized lengths run in software (decline). */
    if (sz == 0 || (sz % XASU_AES_BLOCK_SIZE_IN_BYTES) != 0 ||
        sz > XASU_ASU_DMA_MAX_TRANSFER_LENGTH) {
        return CRYPTOCB_UNAVAILABLE;
    }

    ret = wc_AsuCipherKeySize(aes->keylen, &keySize);
    if (ret != 0) {
        return ret;
    }

    XMEMSET(&req, 0, sizeof(req));
    req.keyObj.KeyAddress     = (u64)(UINTPTR)aes->devKey;
    req.keyObj.KeySize        = keySize;
    req.keyObj.KeySrc         = XASU_AES_USER_KEY_0;

    req.params.InputDataAddr  = (u64)(UINTPTR)in;
    req.params.OutputDataAddr = (u64)(UINTPTR)out;
    req.params.KeyObjectAddr  = (u64)(UINTPTR)&req.keyObj;
    req.params.DataLen        = sz;
    req.params.EngineMode     = engineMode;
    req.params.OperationFlags =
        (u8)(XASU_AES_INIT | XASU_AES_UPDATE | XASU_AES_FINAL);
    req.params.IsLast         = (u8)XASU_TRUE;
    if (enc) {
        req.params.OperationType = (u8)XASU_AES_ENCRYPT_OPERATION;
    }
    else {
        req.params.OperationType = (u8)XASU_AES_DECRYPT_OPERATION;
    }
    if (iv != NULL) {
        req.params.IvAddr = (u64)(UINTPTR)iv;
        req.params.IvLen  = XASU_AES_IV_SIZE_128BIT_IN_BYTES;
    }

    WC_ASU_PRINTF("[ASU] cipher mode=%d enc=%d keyLen=%u sz=%u\r\n",
        (int)engineMode, enc, (unsigned int)aes->keylen, (unsigned int)sz);

    /* The ASU DMAs the key object, key, IV and input from memory, so clean them
     * out; invalidate the output afterwards so the CPU sees the DMA'd result. */
    wc_AsuCacheFlush(aes->devKey, aes->keylen);
    wc_AsuCacheFlush(&req.keyObj, sizeof(req.keyObj));
    if (iv != NULL) {
        wc_AsuCacheFlush(iv, XASU_AES_IV_SIZE_128BIT_IN_BYTES);
    }
    wc_AsuCacheFlush(in, sz);

    status = wc_AsuTransact(wc_AsuCipherSubmit, &req, NULL);
    if (status != XST_SUCCESS) {
        return WC_HW_E;
    }

    wc_AsuCacheInvalidate(out, sz);

    return 0;
}

/* AES-CBC. The IV comes from aes->reg and, on success, is updated to the last
 * ciphertext block so a chained call continues correctly. */
static int wc_AsuCipherCbc(wc_CryptoInfo* info)
{
    byte* ctr;
    int   ret;
    byte  lastBlock[WC_AES_BLOCK_SIZE];

    /* Reference info->cipher.aescbc fields directly; no aliasing locals. */
    if (info == NULL || info->cipher.aescbc.aes == NULL ||
        info->cipher.aescbc.out == NULL || info->cipher.aescbc.in == NULL) {
        return BAD_FUNC_ARG;
    }
    if (info->cipher.aescbc.sz == 0 ||
        (info->cipher.aescbc.sz % WC_AES_BLOCK_SIZE) != 0) {
        return CRYPTOCB_UNAVAILABLE;
    }

    /* CBC chaining IV is aes->reg. For decrypt the next IV is the last input
     * block; capture it now in case out aliases in. */
    ctr = (byte*)info->cipher.aescbc.aes->reg;
    if (!info->cipher.enc) {
        XMEMCPY(lastBlock, info->cipher.aescbc.in +
            (info->cipher.aescbc.sz - WC_AES_BLOCK_SIZE), WC_AES_BLOCK_SIZE);
    }

    ret = wc_AsuCipherOneShot(info->cipher.aescbc.aes, info->cipher.aescbc.out,
        info->cipher.aescbc.in, info->cipher.aescbc.sz, info->cipher.enc,
        (u8)XASU_AES_CBC_MODE, ctr);
    if (ret != 0) {
        return ret;
    }

    /* Update aes->reg to the last ciphertext block for a chained call. */
    if (info->cipher.enc) {
        XMEMCPY(ctr, info->cipher.aescbc.out +
            (info->cipher.aescbc.sz - WC_AES_BLOCK_SIZE), WC_AES_BLOCK_SIZE);
    }
    else {
        XMEMCPY(ctr, lastBlock, WC_AES_BLOCK_SIZE);
    }

    return 0;
}

/* AES-ECB. No IV and no chaining state. */
static int wc_AsuCipherEcb(wc_CryptoInfo* info)
{
    /* Reference info->cipher.aesecb fields directly; no aliasing locals. */
    if (info == NULL || info->cipher.aesecb.aes == NULL ||
        info->cipher.aesecb.out == NULL || info->cipher.aesecb.in == NULL) {
        return BAD_FUNC_ARG;
    }

    return wc_AsuCipherOneShot(info->cipher.aesecb.aes, info->cipher.aesecb.out,
        info->cipher.aesecb.in, info->cipher.aesecb.sz, info->cipher.enc,
        (u8)XASU_AES_ECB_MODE, NULL);
}

#ifdef WOLFSSL_AES_COUNTER
/* AES-CTR via the ASU CTR engine (counter in aes->reg). The ASU counter field
 * diverges from wolfSSL's full 128-bit increment only on wrap, so decline (to
 * software) when the op would overflow the low 32-bit counter, has leftover
 * keystream, or is non block-aligned. */
static int wc_AsuCipherCtr(wc_CryptoInfo* info)
{
    byte*  ctr;
    word32 blocks;
    word32 low;
    int    ret;

    /* Reference info->cipher.aesctr fields directly; no aliasing locals. */
    if (info == NULL || info->cipher.aesctr.aes == NULL ||
        info->cipher.aesctr.out == NULL || info->cipher.aesctr.in == NULL) {
        return BAD_FUNC_ARG;
    }
    /* CTR streaming state lives in the Aes context; the ASU starts a fresh
     * counter block, so decline leftover keystream or a non block-aligned size. */
    if (info->cipher.aesctr.aes->left != 0 || info->cipher.aesctr.sz == 0 ||
        (info->cipher.aesctr.sz % WC_AES_BLOCK_SIZE) != 0) {
        return CRYPTOCB_UNAVAILABLE;
    }

    /* Counter is big-endian in aes->reg; the low 32 bits are the last 4 bytes.
     * Decline if the block count would carry past them (ASU wrap divergence). */
    ctr = (byte*)info->cipher.aesctr.aes->reg;
    low = ((word32)ctr[12] << 24) | ((word32)ctr[13] << 16) |
          ((word32)ctr[14] << 8)  |  (word32)ctr[15];
    blocks = info->cipher.aesctr.sz / WC_AES_BLOCK_SIZE;
    if (low > (0xFFFFFFFFU - blocks)) {
        return CRYPTOCB_UNAVAILABLE;
    }

    /* CTR is symmetric; drive the engine encrypt with aes->reg as the counter. */
    ret = wc_AsuCipherOneShot(info->cipher.aesctr.aes, info->cipher.aesctr.out,
        info->cipher.aesctr.in, info->cipher.aesctr.sz, 1,
        (u8)XASU_AES_CTR_MODE, ctr);
    if (ret != 0) {
        return ret;
    }

    /* No carry past the low 32 bits (guarded), so advance only that word to
     * match wolfSSL for a chained call. */
    low += blocks;
    ctr[12] = (byte)(low >> 24);
    ctr[13] = (byte)(low >> 16);
    ctr[14] = (byte)(low >> 8);
    ctr[15] = (byte)(low);

    return 0;
}
#endif /* WOLFSSL_AES_COUNTER */

#ifdef HAVE_AESGCM
/* AES-GCM via the ASU GCM mode (one-shot: key, IV, AAD and tag in one op).
 * Offloads aligned plaintext+AAD with a 128/256 key and 8..16 byte tag; declines
 * non-aligned, AES-192 or out-of-range tag to software. The enc/dec union members
 * share one layout, so the aesgcm_enc view reads either direction's fields. */
static int wc_AsuCipherGcm(wc_CryptoInfo* info)
{
    AsuCipherReq req;
    u32          keySize = 0;
    word32       addl = 0;
    word32       status;
    int          ret;

    if (info == NULL || info->cipher.aesgcm_enc.aes == NULL ||
        info->cipher.aesgcm_enc.iv == NULL ||
        info->cipher.aesgcm_enc.authTag == NULL) {
        return BAD_FUNC_ARG;
    }
    /* Data/AAD buffers must be valid when their length is non-zero. */
    if ((info->cipher.aesgcm_enc.sz != 0) &&
        ((info->cipher.aesgcm_enc.in == NULL) ||
         (info->cipher.aesgcm_enc.out == NULL))) {
        return BAD_FUNC_ARG;
    }
    if ((info->cipher.aesgcm_enc.authInSz != 0) &&
        (info->cipher.aesgcm_enc.authIn == NULL)) {
        return BAD_FUNC_ARG;
    }

    /* The ASU GCM engine needs at least one byte of data or AAD; the empty
     * message with empty AAD (tag-only) case runs in software. */
    if (info->cipher.aesgcm_enc.sz == 0 && info->cipher.aesgcm_enc.authInSz == 0) {
        return CRYPTOCB_UNAVAILABLE;
    }

    /* The ASU client takes whole 16-byte plaintext and AAD within the DMA limit
     * and a 8..16 byte tag; anything else runs in software. */
    if ((info->cipher.aesgcm_enc.sz % XASU_AES_BLOCK_SIZE_IN_BYTES) != 0 ||
        (info->cipher.aesgcm_enc.authInSz % XASU_AES_BLOCK_SIZE_IN_BYTES) != 0 ||
        info->cipher.aesgcm_enc.sz > XASU_ASU_DMA_MAX_TRANSFER_LENGTH ||
        info->cipher.aesgcm_enc.authInSz > XASU_ASU_DMA_MAX_TRANSFER_LENGTH ||
        info->cipher.aesgcm_enc.authTagSz < XASU_AES_RECOMMENDED_TAG_LENGTH_IN_BYTES ||
        info->cipher.aesgcm_enc.authTagSz > XASU_AES_MAX_TAG_LENGTH_IN_BYTES) {
        return CRYPTOCB_UNAVAILABLE;
    }

    ret = wc_AsuCipherKeySize(info->cipher.aesgcm_enc.aes->keylen, &keySize);
    if (ret != 0) {
        return ret;
    }

    XMEMSET(&req, 0, sizeof(req));
    req.keyObj.KeyAddress     = (u64)(UINTPTR)info->cipher.aesgcm_enc.aes->devKey;
    req.keyObj.KeySize        = keySize;
    req.keyObj.KeySrc         = XASU_AES_USER_KEY_0;

    /* The ASU client rejects a non-zero buffer address paired with a zero
     * length, so leave these at the memset-zero default when the length is 0. */
    if (info->cipher.aesgcm_enc.sz != 0) {
        req.params.InputDataAddr  = (u64)(UINTPTR)info->cipher.aesgcm_enc.in;
        req.params.OutputDataAddr = (u64)(UINTPTR)info->cipher.aesgcm_enc.out;
    }
    if (info->cipher.aesgcm_enc.authInSz != 0) {
        req.params.AadAddr        = (u64)(UINTPTR)info->cipher.aesgcm_enc.authIn;
    }
    req.params.KeyObjectAddr  = (u64)(UINTPTR)&req.keyObj;
    req.params.IvAddr         = (u64)(UINTPTR)info->cipher.aesgcm_enc.iv;
    req.params.TagAddr        = (u64)(UINTPTR)info->cipher.aesgcm_enc.authTag;
    req.params.DataLen        = info->cipher.aesgcm_enc.sz;
    req.params.AadLen         = info->cipher.aesgcm_enc.authInSz;
    req.params.IvLen          = info->cipher.aesgcm_enc.ivSz;
    req.params.TagLen         = info->cipher.aesgcm_enc.authTagSz;
    req.params.EngineMode     = (u8)XASU_AES_GCM_MODE;
    req.params.OperationFlags =
        (u8)(XASU_AES_INIT | XASU_AES_UPDATE | XASU_AES_FINAL);
    req.params.IsLast         = (u8)XASU_TRUE;
    if (info->cipher.enc) {
        req.params.OperationType = (u8)XASU_AES_ENCRYPT_OPERATION;
    }
    else {
        req.params.OperationType = (u8)XASU_AES_DECRYPT_OPERATION;
    }

    WC_ASU_PRINTF("[ASU] cipher mode=%d enc=%d keyLen=%u sz=%u aad=%u tag=%u\r\n",
        (int)XASU_AES_GCM_MODE, info->cipher.enc,
        (unsigned int)info->cipher.aesgcm_enc.aes->keylen,
        (unsigned int)info->cipher.aesgcm_enc.sz,
        (unsigned int)info->cipher.aesgcm_enc.authInSz,
        (unsigned int)info->cipher.aesgcm_enc.authTagSz);

    /* The ASU DMAs key, IV, AAD, input (and the tag on decrypt) from memory. */
    wc_AsuCacheFlush(info->cipher.aesgcm_enc.aes->devKey,
        info->cipher.aesgcm_enc.aes->keylen);
    wc_AsuCacheFlush(&req.keyObj, sizeof(req.keyObj));
    wc_AsuCacheFlush(info->cipher.aesgcm_enc.iv, info->cipher.aesgcm_enc.ivSz);
    if (info->cipher.aesgcm_enc.authInSz != 0) {
        wc_AsuCacheFlush(info->cipher.aesgcm_enc.authIn,
            info->cipher.aesgcm_enc.authInSz);
    }
    if (info->cipher.aesgcm_enc.sz != 0) {
        wc_AsuCacheFlush(info->cipher.aesgcm_enc.in, info->cipher.aesgcm_enc.sz);
    }
    if (!info->cipher.enc) {
        wc_AsuCacheFlush(info->cipher.aesgcm_enc.authTag,
            info->cipher.aesgcm_enc.authTagSz);
    }

    status = wc_AsuTransact(wc_AsuCipherSubmit, &req, &addl);

    /* Invalidate the CPU's view of the ASU-written output (and the tag on encrypt). */
    if (info->cipher.aesgcm_enc.sz != 0) {
        wc_AsuCacheInvalidate(info->cipher.aesgcm_enc.out,
            info->cipher.aesgcm_enc.sz);
    }
    if (info->cipher.enc) {
        wc_AsuCacheInvalidate(info->cipher.aesgcm_enc.authTag,
            info->cipher.aesgcm_enc.authTagSz);
    }

    /* Decrypt reports a tag mismatch as a failure; surface it as AES_GCM_AUTH_E.
     * Encrypt success is confirmed by TAG_READ, decrypt by TAG_MATCHED. */
    if (status != XST_SUCCESS) {
        if (!info->cipher.enc) {
            return AES_GCM_AUTH_E;
        }
        return WC_HW_E;
    }
    if (info->cipher.enc) {
        if (addl != (word32)XASU_AES_TAG_READ) {
            return WC_HW_E;
        }
    }
    else if (addl != (word32)XASU_AES_TAG_MATCHED) {
        return AES_GCM_AUTH_E;
    }

    return 0;
}
#endif /* HAVE_AESGCM */

/* Single entry point for the cipher engine, reached through the crypto callback
 * dispatcher. Handles AES-CBC, AES-ECB, AES-CTR and AES-GCM. */
int wc_AsuCipher(wc_CryptoInfo* info)
{
    if (info == NULL) {
        return BAD_FUNC_ARG;
    }
    if (info->algo_type != WC_ALGO_TYPE_CIPHER) {
        return CRYPTOCB_UNAVAILABLE;
    }

    switch (info->cipher.type) {
    #ifdef HAVE_AES_CBC
        case WC_CIPHER_AES_CBC:
            return wc_AsuCipherCbc(info);
    #endif
    #ifdef HAVE_AES_ECB
        case WC_CIPHER_AES_ECB:
            return wc_AsuCipherEcb(info);
    #endif
    #ifdef WOLFSSL_AES_COUNTER
        case WC_CIPHER_AES_CTR:
            return wc_AsuCipherCtr(info);
    #endif
    #ifdef HAVE_AESGCM
        case WC_CIPHER_AES_GCM:
            return wc_AsuCipherGcm(info);
    #endif
        default:
            return CRYPTOCB_UNAVAILABLE;
    }
}

#endif /* WOLFSSL_VERSAL_GEN2_ASU_CIPHER */
