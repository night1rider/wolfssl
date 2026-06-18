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
    if (sz == 0 || (sz % XASU_AES_BLOCK_SIZE_IN_BYTES) != 0) {
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
    Aes*        aes;
    byte*       out;
    const byte* in;
    word32      sz;
    int         enc;
    int         ret;
    byte        lastBlock[WC_AES_BLOCK_SIZE];

    if (info == NULL) {
        return BAD_FUNC_ARG;
    }

    aes = info->cipher.aescbc.aes;
    out = info->cipher.aescbc.out;
    in  = info->cipher.aescbc.in;
    sz  = info->cipher.aescbc.sz;
    enc = info->cipher.enc;

    if (aes == NULL || out == NULL || in == NULL) {
        return BAD_FUNC_ARG;
    }
    if (sz == 0 || (sz % WC_AES_BLOCK_SIZE) != 0) {
        return CRYPTOCB_UNAVAILABLE;
    }

    /* For decrypt the next IV is the last input block; capture it now in case
     * out aliases in. */
    if (!enc) {
        XMEMCPY(lastBlock, in + (sz - WC_AES_BLOCK_SIZE), WC_AES_BLOCK_SIZE);
    }

    ret = wc_AsuCipherOneShot(aes, out, in, sz, enc, (u8)XASU_AES_CBC_MODE,
        (const byte*)aes->reg);
    if (ret != 0) {
        return ret;
    }

    if (enc) {
        XMEMCPY((byte*)aes->reg, out + (sz - WC_AES_BLOCK_SIZE),
            WC_AES_BLOCK_SIZE);
    }
    else {
        XMEMCPY((byte*)aes->reg, lastBlock, WC_AES_BLOCK_SIZE);
    }

    return 0;
}

/* AES-ECB. No IV and no chaining state. */
static int wc_AsuCipherEcb(wc_CryptoInfo* info)
{
    Aes*        aes;
    byte*       out;
    const byte* in;
    word32      sz;
    int         enc;

    if (info == NULL) {
        return BAD_FUNC_ARG;
    }

    aes = info->cipher.aesecb.aes;
    out = info->cipher.aesecb.out;
    in  = info->cipher.aesecb.in;
    sz  = info->cipher.aesecb.sz;
    enc = info->cipher.enc;

    if (aes == NULL || out == NULL || in == NULL) {
        return BAD_FUNC_ARG;
    }

    return wc_AsuCipherOneShot(aes, out, in, sz, enc, (u8)XASU_AES_ECB_MODE,
        NULL);
}

/* Single entry point for the cipher engine, reached through the crypto callback
 * dispatcher. Only AES-CBC and AES-ECB are handled. */
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
        default:
            return CRYPTOCB_UNAVAILABLE;
    }
}

#endif /* WOLFSSL_VERSAL_GEN2_ASU_CIPHER */
