/* asu_cmac.c
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

/* ASU AES-CMAC for the wolfSSL crypto callback. The ASU takes the CMAC message
 * through the AAD path, which the client accepts only in whole 16-byte blocks,
 * and the ASU CMAC context cannot be exported between client calls. So the
 * message is accumulated per Cmac context (a buffer hung off cmac->devCtx with
 * the wolfSSL _wc_Hash_Grow helper) and the whole CMAC is produced in one ASU
 * operation at finalize.
 *
 * wc_InitCmac returns early when this INIT handler succeeds, skipping its
 * software k1/k2 setup, so once a context is accepted at INIT every later update
 * and final must be handled here (no mid-stream decline). The message length is
 * unknown at INIT, so at FINAL a whole-block message is offloaded to the ASU and
 * a non block-aligned or empty message is computed in software over the buffer.
 * AES-192 and the one-shot non-aligned case are declined up front instead.
 *
 * The per-context buffer is freed at FINAL; an abandoned context (init/update
 * with no final) leaks it, matching wolfSSL's own cmac->msg behaviour. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_VERSAL_GEN2_ASU_CMAC

#include <wolfssl/wolfcrypt/port/xilinx/versal_gen2_asu/asu_cmac.h>
#include <wolfssl/wolfcrypt/port/xilinx/versal_gen2_asu/asu_util.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/cmac.h>
#include <wolfssl/wolfcrypt/hash.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include "xasu_aes.h"
#include "xasu_aesinfo.h"
#include "xasu_def.h"
#include "xasu_status.h"
#include "xstatus.h"

#ifndef WOLFSSL_HASH_KEEP
    #error "WOLFSSL_VERSAL_GEN2_ASU_CMAC requires WOLFSSL_HASH_KEEP (_wc_Hash_Grow)"
#endif

/* Per CMAC context state, held in the wolfSSL Cmac devCtx: the key captured at
 * init and the message accumulated across updates. */
typedef struct {
    byte*  msg;          /* accumulated message */
    word32 used;         /* bytes accumulated */
    word32 len;          /* buffer capacity */
    byte   key[AES_MAX_KEY_SIZE / 8];
    word32 keyLen;
} AsuCmacKeep;

/* One ASU AES request: the params block and the key object it points at. */
typedef struct {
    XAsu_AesParams    params;
    XAsu_AesKeyObject keyObj;
} AsuCmacReq;

/* Submit thunk: queue one ASU AES operation. Called by wc_AsuTransact with the
 * submit lock held, so it only queues the request. */
static int wc_AsuCmacSubmit(XAsu_ClientParams* params, void* ctx)
{
    AsuCmacReq* req = (AsuCmacReq*)ctx;

    if (params == NULL || req == NULL) {
        return XST_FAILURE;
    }

    return XAsu_AesOperation(params, &req->params);
}

/* Map a wolfSSL key length to the ASU key size. Returns CRYPTOCB_UNAVAILABLE for
 * AES-192 and any other unsupported length so wolfSSL falls back to software. */
static int wc_AsuCmacKeySize(word32 keyLen, u32* keySize)
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

/* Release a kept context record. The message buffer holds the authenticated
 * message, so it is zeroed before being freed. */
static void wc_AsuCmacKeepFree(AsuCmacKeep* keep)
{
    if (keep == NULL) {
        return;
    }
    if (keep->msg != NULL) {
        ForceZero(keep->msg, keep->len);
        XFREE(keep->msg, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    ForceZero(keep, sizeof(*keep));
    XFREE(keep, NULL, DYNAMIC_TYPE_TMP_BUFFER);
}

/* Compute the 16-byte CMAC over the whole message in one ASU operation. The
 * message goes through the block-aligned AAD path; CMAC takes no IV. Caller has
 * checked the key size and that msgLen is non-zero and block aligned. */
static int wc_AsuCmacHw(const byte* key, word32 keyLen, u32 keySize,
    const byte* msg, word32 msgLen, byte* tag)
{
    AsuCmacReq req;
    word32     addl = 0;
    word32     status;
    byte       iv[XASU_AES_IV_SIZE_128BIT_IN_BYTES];

    if (key == NULL || msg == NULL || tag == NULL || msgLen == 0) {
        return BAD_FUNC_ARG;
    }

    /* CMAC has no IV but the firmware loads one for every non-ECB mode, so pass
     * the all-zero CBC-MAC start vector; a zero IvLen would make it DMA 0 bytes. */
    XMEMSET(iv, 0, sizeof(iv));

    XMEMSET(&req, 0, sizeof(req));
    req.keyObj.KeyAddress     = (u64)(UINTPTR)key;
    req.keyObj.KeySize        = keySize;
    req.keyObj.KeySrc         = XASU_AES_USER_KEY_0;

    req.params.KeyObjectAddr  = (u64)(UINTPTR)&req.keyObj;
    req.params.AadAddr        = (u64)(UINTPTR)msg;
    req.params.AadLen         = msgLen;
    req.params.IvAddr         = (u64)(UINTPTR)iv;
    req.params.IvLen          = XASU_AES_IV_SIZE_128BIT_IN_BYTES;
    req.params.TagAddr        = (u64)(UINTPTR)tag;
    req.params.TagLen         = XASU_AES_MAX_TAG_LENGTH_IN_BYTES;
    req.params.EngineMode     = (u8)XASU_AES_CMAC_MODE;
    req.params.OperationFlags =
        (u8)(XASU_AES_INIT | XASU_AES_UPDATE | XASU_AES_FINAL);
    req.params.IsLast         = (u8)XASU_TRUE;
    req.params.OperationType  = (u8)XASU_AES_ENCRYPT_OPERATION;

    WC_ASU_PRINTF("[ASU] cmac mode=%d keyLen=%u msgLen=%u tag=%u\r\n",
        (int)XASU_AES_CMAC_MODE, (unsigned int)keyLen, (unsigned int)msgLen,
        (unsigned int)XASU_AES_MAX_TAG_LENGTH_IN_BYTES);

    /* The ASU DMAs the key object, key, IV and message from memory; invalidate
     * the tag afterwards so the CPU sees the DMA'd result. */
    wc_AsuCacheFlush(key, keyLen);
    wc_AsuCacheFlush(&req.keyObj, sizeof(req.keyObj));
    wc_AsuCacheFlush(iv, sizeof(iv));
    wc_AsuCacheFlush(msg, msgLen);

    status = wc_AsuTransact(wc_AsuCmacSubmit, &req, &addl);

    wc_AsuCacheInvalidate(tag, XASU_AES_MAX_TAG_LENGTH_IN_BYTES);

    if (status != XST_SUCCESS) {
        return WC_HW_E;
    }
    if (addl != (word32)XASU_AES_TAG_READ) {
        return WC_HW_E;
    }

    return 0;
}

/* Produce the CMAC tag for a finished message: offload whole 16-byte blocks to
 * the ASU, otherwise compute in software over the same buffer. outSz is the
 * caller's requested (possibly truncated) tag length. */
static int wc_AsuCmacProduce(const byte* key, word32 keyLen, const byte* msg,
    word32 msgLen, byte* out, word32* outSz)
{
    byte   tag[XASU_AES_MAX_TAG_LENGTH_IN_BYTES];
    u32    keySize = 0;
    int    ret;

    if (out == NULL || outSz == NULL) {
        return BAD_FUNC_ARG;
    }
    if (*outSz < WC_CMAC_TAG_MIN_SZ || *outSz > WC_CMAC_TAG_MAX_SZ) {
        return BUFFER_E;
    }

    /* Whole-block, non-empty message with a supported key runs on the ASU. */
    if ((msgLen != 0) && ((msgLen % XASU_AES_BLOCK_SIZE_IN_BYTES) == 0) &&
        (msgLen <= XASU_ASU_DMA_MAX_TRANSFER_LENGTH) &&
        (wc_AsuCmacKeySize(keyLen, &keySize) == 0)) {
        ret = wc_AsuCmacHw(key, keyLen, keySize, msg, msgLen, tag);
        if (ret != 0) {
            return ret;
        }
        XMEMCPY(out, tag, *outSz);
        ForceZero(tag, sizeof(tag));
        return 0;
    }

    /* Empty or non block-aligned message: we already committed at init, so the
     * software k1/k2 state was not set up; compute the whole CMAC in software. */
    return wc_AesCmacGenerate(out, outSz, msg, msgLen, key, keyLen);
}

/* Single entry point for the CMAC engine, reached through the crypto callback
 * dispatcher (WC_ALGO_TYPE_CMAC). */
int wc_AsuCmac(wc_CryptoInfo* info)
{
    Cmac*        cmac;
    AsuCmacKeep* keep;
    int          ret;

    if (info == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Context free: release any per-context buffer hung off devCtx. Reached via
     * WC_ALGO_TYPE_FREE when a context is freed (e.g. never finalized). */
    if (info->algo_type == WC_ALGO_TYPE_FREE) {
        cmac = (Cmac*)info->free.obj;
        if (cmac != NULL && cmac->devCtx != NULL) {
            wc_AsuCmacKeepFree((AsuCmacKeep*)cmac->devCtx);
            cmac->devCtx = NULL;
        }
        return CRYPTOCB_UNAVAILABLE;
    }

    if (info->cmac.cmac == NULL) {
        return BAD_FUNC_ARG;
    }
    if (info->cmac.type != WC_CMAC_AES) {
        return CRYPTOCB_UNAVAILABLE;
    }
    cmac = info->cmac.cmac;

    /* One-shot generate (key, message and output all supplied). Offload a whole
     * block message; otherwise decline so wolfSSL runs it in software. */
    if (info->cmac.key != NULL && info->cmac.out != NULL) {
        u32 keySize = 0;
        if ((info->cmac.inSz == 0) ||
            ((info->cmac.inSz % XASU_AES_BLOCK_SIZE_IN_BYTES) != 0) ||
            (info->cmac.inSz > XASU_ASU_DMA_MAX_TRANSFER_LENGTH) ||
            (wc_AsuCmacKeySize(info->cmac.keySz, &keySize) != 0)) {
            return CRYPTOCB_UNAVAILABLE;
        }
        if ((info->cmac.outSz == NULL) ||
            (*info->cmac.outSz < WC_CMAC_TAG_MIN_SZ) ||
            (*info->cmac.outSz > WC_CMAC_TAG_MAX_SZ)) {
            return CRYPTOCB_UNAVAILABLE;
        }
        return wc_AsuCmacProduce(info->cmac.key, info->cmac.keySz,
            info->cmac.in, info->cmac.inSz, info->cmac.out, info->cmac.outSz);
    }

    /* init(): capture the key and start a per-context buffer. AES-192 and other
     * unsupported key sizes are declined so wolfSSL handles the whole CMAC. */
    if (info->cmac.key != NULL) {
        u32 keySize = 0;
        if (info->cmac.keySz > sizeof(((AsuCmacKeep*)0)->key) ||
            (wc_AsuCmacKeySize(info->cmac.keySz, &keySize) != 0)) {
            return CRYPTOCB_UNAVAILABLE;
        }
        keep = (AsuCmacKeep*)XMALLOC(sizeof(AsuCmacKeep), NULL,
            DYNAMIC_TYPE_TMP_BUFFER);
        if (keep == NULL) {
            return MEMORY_E;
        }
        XMEMSET(keep, 0, sizeof(*keep));
        XMEMCPY(keep->key, info->cmac.key, info->cmac.keySz);
        keep->keyLen = info->cmac.keySz;
        cmac->devCtx = keep;
        /* wc_InitCmac returns early on our success and skips its own type setup,
         * so persist it; later update/final read cmac->type to reach us. */
        cmac->type = info->cmac.type;
        return 0;
    }

    keep = (AsuCmacKeep*)cmac->devCtx;

    /* update(): accumulate the message with the wolfSSL grow helper. A NULL
     * devCtx means init declined, so let wolfSSL run this in software. */
    if (info->cmac.in != NULL && info->cmac.out == NULL) {
        if (keep == NULL) {
            return CRYPTOCB_UNAVAILABLE;
        }
        return _wc_Hash_Grow(&keep->msg, &keep->used, &keep->len,
            info->cmac.in, (int)info->cmac.inSz, NULL);
    }

    /* final(): produce the CMAC over the whole accumulated message, then release
     * the buffer. A NULL devCtx means init declined; defer to software. */
    if (info->cmac.out != NULL) {
        if (keep == NULL) {
            return CRYPTOCB_UNAVAILABLE;
        }
        ret = wc_AsuCmacProduce(keep->key, keep->keyLen, keep->msg, keep->used,
            info->cmac.out, info->cmac.outSz);
        wc_AsuCmacKeepFree(keep);
        cmac->devCtx = NULL;
        return ret;
    }

    return CRYPTOCB_UNAVAILABLE;
}

#endif /* WOLFSSL_VERSAL_GEN2_ASU_CMAC */
