/* max3266x.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_MAX3266X) || defined(WOLFSSL_MAX3266X_OLD)

#include <stdint.h>
#include <stdarg.h>

#include <wolfssl/wolfcrypt/wolfmath.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/port/maxim/max3266x.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#if defined(USE_FAST_MATH)
    #error  MXC Not Compatible with Fast Math
    #include <wolfssl/wolfcrypt/tfm.h>
    #define MXC_WORD_SIZE               DIGIT_BIT
#elif defined(WOLFSSL_SP_MATH_ALL)
    #include <wolfssl/wolfcrypt/sp_int.h>
    #define MXC_WORD_SIZE               SP_WORD_SIZE
#endif

#define MXC_MAA_MAX_SIZE (2048)/MXC_WORD_SIZE

int wc_MXC_TPU_Init(void)
{
    /* Initialize the TPU device */
    if(MXC_TPU_Init(MXC_SYS_PERIPH_CLOCK_TRNG) != EXIT_SUCCESS){
        WOLFSSL_MSG("Device did not initialize");
        return RNG_FAILURE_E;
    }
    return 0;
}

int wc_MXC_TPU_Shutdown(void)
{
    /* Shutdown the TPU device */
    #if defined(WOLFSSL_MAX3266X_OLD)
        MXC_TPU_Shutdown(); /* Is a void return in older SDK */
    #else
        if(MXC_TPU_Shutdown(MXC_SYS_PERIPH_CLOCK_TRNG) != EXIT_SUCCESS){
            WOLFSSL_MSG("Device did not shutdown");
            return RNG_FAILURE_E;
        }
    #endif
    WOLFSSL_MSG("TPU Hardware Shutdown");
    return 0;
}


/* Convert Error Codes Correctly */
/* TODO: Convert to correct wolfCrypt Codes */
/* TODO: Add wolfssl Message Statements to report HW issue on bad return */
int wc_MXC_error(int *ret)
{
    switch(*ret){
        case(E_SUCCESS):
            return 0;

        case(E_NULL_PTR):
            return E_NULL_PTR;

        case(E_INVALID): /* Process Failed */
            return E_INVALID;

        case(E_BAD_PARAM):
            return BAD_FUNC_ARG;

        case(E_BAD_STATE):
            return E_BAD_STATE;

        default:
            *ret = WC_HW_E; /* If something else return HW Error */
            return *ret;
    }
}


#if defined(MAX3266X_RNG)

/* Use this RNG_FAILURE_E for RNG Errors*/
int wc_MXC_TRNG_Random(unsigned char* output, unsigned int sz)
{
    if(MXC_TPU_Init(MXC_SYS_PERIPH_CLOCK_TRNG) != E_SUCCESS){
        WOLFSSL_MSG("TRNG Device did not initialize");
        return RNG_FAILURE_E;
    }
    /* void return function */
    MXC_TPU_TRNG_Read(MXC_TRNG, output, sz);
    WOLFSSL_MSG("TRNG Hardware Used");
    return 0;
}
#endif /* MAX3266x_RNG */

#if defined(MAX3266X_AES)
int wc_MXC_TPU_AesEncrypt(const char *in, const char *iv,
                            const char *enc_key,
                            MXC_TPU_MODE_TYPE mode,
                            unsigned int data_size,
                            char *out, unsigned int keySize)
{
    int status;
    status = wolfSSL_CryptHwMutexLock();
    WOLFSSL_MSG("AES HW Encryption");
        if (status != 0){
            WOLFSSL_MSG("Hardware Mutex Failure");
            return status;
        }
        switch (keySize) {
            case MXC_AES_KEY_128_LEN:
                MXC_TPU_Cipher_Config(mode, MXC_TPU_CIPHER_AES128);
                status = MXC_TPU_Cipher_AES_Encrypt(in, iv, enc_key,
                            MXC_TPU_CIPHER_AES128, mode, data_size, out);
                WOLFSSL_MSG("AES HW Acceleration Used: 128 Bit");
                break;
            case MXC_AES_KEY_192_LEN:
                MXC_TPU_Cipher_Config(mode, MXC_TPU_CIPHER_AES192);
                status = MXC_TPU_Cipher_AES_Encrypt(in, iv, enc_key,
                            MXC_TPU_CIPHER_AES192, mode, data_size, out);
                WOLFSSL_MSG("AES HW Acceleration Used: 192 Bit");
                break;
            case MXC_AES_KEY_256_LEN:
                MXC_TPU_Cipher_Config(mode, MXC_TPU_CIPHER_AES256);
                status = MXC_TPU_Cipher_AES_Encrypt(in, iv, enc_key,
                            MXC_TPU_CIPHER_AES256, mode, data_size, out);
                WOLFSSL_MSG("AES HW Acceleration Used: 256 Bit");
                break;
            default:
                WOLFSSL_MSG("AES HW ERROR: Length Not Supported");
                wolfSSL_CryptHwMutexUnLock();
                return WC_HW_E;
            break;
    }
    wolfSSL_CryptHwMutexUnLock();
    if (status != 0){
        WOLFSSL_MSG("AES HW Acceleration Error Occured");
        return WC_HW_E;
    }
    return 0;
}

int wc_MXC_TPU_AesDecrypt(const char *in, const char *iv,
                            const char *dec_key,
                            MXC_TPU_MODE_TYPE mode,
                            unsigned int data_size,
                            char *out, unsigned int keySize)
{
    int status;
    status = wolfSSL_CryptHwMutexLock();
    if (status != 0){
        return status;
    }
    switch (keySize) {
        case MXC_AES_KEY_128_LEN:
            MXC_TPU_Cipher_Config(mode, MXC_TPU_CIPHER_AES128);
            status = MXC_TPU_Cipher_AES_Decrypt(in, iv, dec_key,
                        MXC_TPU_CIPHER_AES128, mode, data_size, out);
            WOLFSSL_MSG("AES HW Acceleration Used: 128 Bit");
            break;
        case MXC_AES_KEY_192_LEN:
            MXC_TPU_Cipher_Config(mode, MXC_TPU_CIPHER_AES192);
            status = MXC_TPU_Cipher_AES_Decrypt(in, iv, dec_key,
                        MXC_TPU_CIPHER_AES192, mode, data_size, out);
            WOLFSSL_MSG("AES HW Acceleration Used: 192 Bit");
            break;
        case MXC_AES_KEY_256_LEN:
            MXC_TPU_Cipher_Config(mode, MXC_TPU_CIPHER_AES256);
            status = MXC_TPU_Cipher_AES_Decrypt(in, iv, dec_key,
                        MXC_TPU_CIPHER_AES256, mode, data_size, out);
            WOLFSSL_MSG("AES HW Acceleration Used: 256 Bit");
            break;
        default:
            WOLFSSL_MSG("AES HW ERROR: Length Not Supported");
            wolfSSL_CryptHwMutexUnLock();
            return WC_HW_E;
        break;
    }

    wolfSSL_CryptHwMutexUnLock();
    if (status != 0){
        WOLFSSL_MSG("AES HW Acceleration Error Occured");
        return WC_HW_E;
    }
    return 0;
}

#endif

#if defined(MAX3266X_SHA)

int wc_MXC_TPU_SHA_Init(wc_MXC_Sha *hash)
{
    if (hash == NULL) {
        return BAD_FUNC_ARG; /* Appropriate error handling for null argument */
    }
    hash->msg = NULL;
    hash->used = 0;
    hash->size = 0;
    return 0;
}

int wc_MXC_TPU_SHA_Update(wc_MXC_Sha *hash, const unsigned char* data,
                            unsigned int size)
{
    void *p;
    if(size != (0 || NULL)){
        if ((hash== NULL) || (data == NULL))
            return BAD_FUNC_ARG;
        if (hash->size < hash->used+size) {
            if (hash->msg == NULL) {
                p = XMALLOC(hash->used+size, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            }
            else {
                #ifdef WOLFSSL_NO_REALLOC
                p = XMALLOC(hash->used + size, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                if (p != NULL) {
                    XMEMCPY(p, hash->msg, hash->used);
                    XFREE(hash->msg, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                }
                #else
                p = XREALLOC(hash->msg, hash->used+size, NULL,
                                DYNAMIC_TYPE_TMP_BUFFER);
                #endif

            }
            if (p == NULL){
                return -1;
            }
            hash->msg = p;
            hash->size = hash->used+size;
        }
        XMEMCPY(hash->msg+hash->used, data, size);
        hash->used += size;
        if(hash->msg == NULL){
            return BAD_FUNC_ARG;
        }
    }
    return 0;
}

int wc_MXC_TPU_SHA_GetHash(wc_MXC_Sha *hash, unsigned char* digest,
                                MXC_TPU_HASH_TYPE algo)
{
    int status;
    status = wc_MXC_TPU_SHA_GetDigest(hash, digest, algo);
    /* True Case that msg is an empty string */
    if(status == 1){
        return 0;
    }
    /* False Case where msg needs to be processed */
    else if (status == 0){
        status = wolfSSL_CryptHwMutexLock();
        if(wc_MXC_error(&status) != 0){

            return status;
        }
        MXC_TPU_Init(MXC_SYS_PERIPH_CLOCK_TPU);
        MXC_TPU_Hash_Config(algo);
        status = MXC_TPU_Hash_SHA((const char *)hash->msg, algo, hash->size,
                                         (char *)digest);
        WOLFSSL_MSG("SHA HW Acceleration Used");
        wolfSSL_CryptHwMutexUnLock();
        if(wc_MXC_error(&status) != 0){
            WOLFSSL_MSG("SHA HW Error Occured");
            return status;
        }
    }
    /* Error Occured */
    return status;
}

int wc_MXC_TPU_SHA_Final(wc_MXC_Sha *hash, unsigned char* digest,
                                    MXC_TPU_HASH_TYPE algo)
{
    int status;
    status = wc_MXC_TPU_SHA_GetHash(hash, digest, algo);
    if (status != 0){
        return status;
    }
    XFREE(hash->msg, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    status = wc_MXC_TPU_SHA_Init(hash);
    if (status != 0){
        return status;
    }
    return status;
}

int wc_MXC_TPU_SHA_Copy(wc_MXC_Sha* src, wc_MXC_Sha* dst)
{
    if (src == NULL || dst == NULL) {
        return BAD_FUNC_ARG;
    }
    dst->used = src->used;
    dst->size = src->size;
    XMEMCPY(dst->hash, src->hash, sizeof(dst->hash));
    return XMEMCMP(dst->hash, src->hash, sizeof(dst->hash));
}

void wc_MXC_TPU_SHA_Free(wc_MXC_Sha* hash)
{
    XFREE(hash->msg, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    hash->msg = NULL;
    wc_MXC_TPU_SHA_Init(hash);
    return;
}

/* Acts as a True/False if true it will provide the stored digest */
/* for the edge case of an empty string */
int wc_MXC_TPU_SHA_GetDigest(wc_MXC_Sha *hash, unsigned char* digest,
                                        MXC_TPU_HASH_TYPE algo)
{
    if(hash->msg == 0 && hash->size == 0 && digest != NULL){
        switch(algo){
            #ifndef NO_SHA256
            case MXC_TPU_HASH_SHA256:
                XMEMCPY(digest, MXC_EMPTY_DIGEST_SHA256, WC_SHA256_DIGEST_SIZE);
                break;
            #endif
            default:
                return BAD_FUNC_ARG;
        }
        return 1; /* True */
    }
    return 0; /* False */
}

#if !defined(NO_SHA256)

WOLFSSL_API int wc_InitSha256_ex(wc_Sha256* sha256, void* heap, int devId)
{
    if (sha256 == NULL){
        return BAD_FUNC_ARG;
    }
    (void)heap;
    (void)devId;
    return wc_MXC_TPU_SHA_Init((wc_MXC_Sha *)sha256);
}

WOLFSSL_API int wc_InitSha256(wc_Sha256* sha256)
{
    return wc_InitSha256_ex(sha256, NULL, INVALID_DEVID);
}

WOLFSSL_API int wc_Sha256Update(wc_Sha256* sha256, const unsigned char* data,
                                        unsigned int len)
{
    return wc_MXC_TPU_SHA_Update(sha256, data, len);
}

WOLFSSL_API int wc_Sha256Final(wc_Sha256* sha256, unsigned char* hash)
{
    return wc_MXC_TPU_SHA_Final((wc_MXC_Sha *)sha256, hash,
                                        MXC_TPU_HASH_SHA256);
}

WOLFSSL_API int wc_Sha256GetHash(wc_Sha256* sha256, unsigned char* hash)
{
    return wc_MXC_TPU_SHA_GetHash((wc_MXC_Sha *)sha256, hash,
                                        MXC_TPU_HASH_SHA256);
}

WOLFSSL_API int wc_Sha256Copy(wc_Sha256* src, wc_Sha256* dst)
{
    return wc_MXC_TPU_SHA_Copy((wc_MXC_Sha *)src, (wc_MXC_Sha *)dst);
}

WOLFSSL_API void wc_Sha256Free(wc_Sha256* sha256)
{
    wc_MXC_TPU_SHA_Free((wc_MXC_Sha *)sha256);
    return;
}

#endif

#endif /* MAX3266X_SHA */

#if defined(MAX3266X_MATH)

int wc_MXC_MAA_init(unsigned int len)
{
    int status;
    WOLFSSL_MSG("Setting Hardware Mutex and Starting MAA");
    status = wolfSSL_CryptHwMutexLock();
    if (status != EXIT_SUCCESS){
        return status;
    }
    status = MXC_TPU_MAA_Init(len);
    return wc_MXC_error(&status); /* Return Status of Init */
}

int wc_MXC_MAA_Shutdown(void)
{
    int status;
    WOLFSSL_MSG("Unlocking Hardware Mutex and Shutting Down MAA");
    status = MXC_TPU_MAA_Shutdown();
    if (status == E_BAD_PARAM){ /* Miss leading, Send WC_HW_ERROR */
                                /* This is returned when MAA cannot stop */
        return WC_HW_E;
    }
    else if(wc_MXC_error(&status) != EXIT_SUCCESS) {
            return status;
    }
    wolfSSL_CryptHwMutexUnLock();
    return status;
}

/* Update used number for mp_int struct for results */
int wc_MXC_MAA_adjustUsed(int *array, unsigned int length)
{
    int lastNonZeroIndex = -1; /* Track the last non-zero index */
    for (int i = 0; i < length; i++) {
        if (array[i] != 0) {
            lastNonZeroIndex = i;
        }
    }
    return (lastNonZeroIndex + 1);
}

void printMAA(mp_int* var, unsigned int len)
{
    if(var != NULL){
        printf("\n");
        for(int i = 0; i < len; i++){
            printf("%08X ", var->dp[i]);
        }
        printf("\n");
    }
}

unsigned int wc_MXC_MAA_Largest(unsigned int count, ...)
{
    va_list args;
    va_start(args, count);
    unsigned int largest = va_arg(args, unsigned int);

    for (int i = 1; i < count; i++) {
        int num = va_arg(args, unsigned int);
        if (num > largest) {
            largest = num;
        }
    }

    va_end(args);
    return largest;
}

int wc_MXC_MAA_Fallback(unsigned int count, ...)
{
    va_list args;
    va_start(args, count);
    int num;
    for (int i = 0; i < count; i++) {
        num = va_arg(args, unsigned int);
        if (num > MXC_MAA_MAX_SIZE) {
            WOLFSSL_MSG("HW Falling Back to Software");
            return EXIT_FAILURE;
        }
    }
    va_end(args);
    WOLFSSL_MSG("HW Can Handle Input");
    return 0;
}



/* Have to zero pad the entire data array up to 256 bytes(2048 bits) */
/* If length > 256 bytes then error */
int wc_MXC_MAA_zeroPad(mp_int* multiplier, mp_int* multiplicand,
                            mp_int* exp, mp_int* mod, mp_int* result,
                            MXC_TPU_MAA_TYPE clc, unsigned int length)
{
    WOLFSSL_MSG("Zero Padding Buffers for Hardware");
    if((length > MXC_MAA_MAX_SIZE)){
        WOLFSSL_MSG("Hardware cannot exceed 2048 bit input");
        return BAD_FUNC_ARG;
    }
    if((result == NULL) || (multiplier == NULL) || (multiplicand == NULL) ||
            ((exp == NULL) && (clc == WC_MXC_TPU_MAA_EXP)) || (mod == NULL))
    {
        return BAD_FUNC_ARG;
    }

    /* Create an array to compare values to to check edge for error edge case */
    mp_digit *zero_tmp = XMALLOC(multiplier->size*(sizeof(mp_digit)), NULL,
                                    DYNAMIC_TYPE_TMP_BUFFER);
    XMEMSET(zero_tmp, 0x00, multiplier->size*(sizeof(mp_digit)));

    /* Check for invalid arguments befor padding */
    switch(clc){
        case(WC_MXC_TPU_MAA_EXP):
            /* Cannot be 0 for a^e mod m operation */
            if(XMEMCMP(zero_tmp, exp, (exp->used*sizeof(mp_digit))) == 0){
                XFREE(zero_tmp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                WOLFSSL_MSG("Cannot use Value 0 for Exp");
                return BAD_FUNC_ARG;
                break;
            }

            /* Padd out rest of data if used != length to ensure no */
            /* garbage is used in calculation */
            if ((exp != NULL) && (clc == WC_MXC_TPU_MAA_EXP)){
                if((exp->dp != NULL) && (exp->used < length)){
                    WOLFSSL_MSG("Zero Padding Exp Buffer");
                    XMEMSET(exp->dp + exp->used, 0x00,
                            sizeof(int) *(length - exp->used));
                }
            }

        /* Fall through to check mod is not 0 */
        case(WC_MXC_TPU_MAA_SQ):
        case(WC_MXC_TPU_MAA_MUL):
        case(WC_MXC_TPU_MAA_SQMUL):
        case(WC_MXC_TPU_MAA_ADD):
        case(WC_MXC_TPU_MAA_SUB):
            /* Cannot be 0 for mod m value */
            if(XMEMCMP(zero_tmp, mod, (exp->used*sizeof(mp_digit))) == 0){
                XFREE(zero_tmp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                WOLFSSL_MSG("Cannot use Value 0 for Exp");
                return BAD_FUNC_ARG;
                break;
            }

            /* Padd out rest of data if used != length to ensure no */
            /* garbage is used in calculation */
            if((multiplier->dp != NULL) && (multiplier->used < length)){
                WOLFSSL_MSG("Zero Padding Multipler Buffer");
                XMEMSET(multiplier->dp + multiplier->used, 0x00,
                    sizeof(int) * (length - multiplier->used));
            }
            if((multiplicand->dp != NULL) && (multiplicand->used < length))
            {
                WOLFSSL_MSG("Zero Padding Multiplicand Buffer");
                XMEMSET(multiplicand->dp + multiplicand->used, 0x00,
                    sizeof(int) * (length - multiplicand->used));
            }
            if((mod->dp != NULL) && (mod->used < length)){
                WOLFSSL_MSG("Zero Padding Mod Buffer");
                XMEMSET(mod->dp + mod->used, 0x00,
                            sizeof(int) *(length - mod->used));
            }
            break;
        default:
            return BAD_FUNC_ARG; /* Invalid clc given */
    }
    /* Free the zero array used to check values */
    XFREE(zero_tmp, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    /* Make sure result is 0 padded */
    if((result->dp != NULL)){
        XMEMSET(result->dp, 0x00, sizeof(int)*(length));
        result->used = length;
    }
    else if(result == NULL){
        return BAD_FUNC_ARG; /* Cannot be null */
    }
    return 0;
}



    /* General Control Over MAA Hardware to handle all needed Cases */
int wc_MXC_MAA_math(mp_int* multipler, mp_int* multiplicand, mp_int* exp,
                                mp_int* mod, mp_int* result,
                                MXC_TPU_MAA_TYPE clc)
{
    int ret;
    int length;
    /* Check if result shares struct pointer */
    mp_int* result_tmp_ptr;
    if((multipler == result) || (multiplicand == result) ||
            (exp == result) || (mod == result)){
            WOLFSSL_MSG("Creating Temp Result Buffer for Hardware");
            mp_int result_tmp;
            result_tmp_ptr = &result_tmp; /* Assign point to temp struct */
    }
    else{
        result_tmp_ptr = result; /* No Shared Point to directly assign */
    }
    if(result_tmp_ptr == NULL){
        WOLFSSL_MSG("tmp ptr is null");
        return MP_VAL;
    }

    if(clc == WC_MXC_TPU_MAA_EXP){
        length = wc_MXC_MAA_Largest(5, multipler->used, multiplicand->used,
                                           exp->used, mod->used, result->used);
    }
    else{
        length = wc_MXC_MAA_Largest(4, multipler->used, multiplicand->used,
                                        mod->used, result->used);
    }

    /* Zero Pad everything if needed */
    ret = wc_MXC_MAA_zeroPad(multipler, multiplicand, exp, mod,
                                    result_tmp_ptr, clc, length);
    if (ret != EXIT_SUCCESS){
        WOLFSSL_MSG("Zero Padding Failed");
        return ret;
    }

    /* Init MAA HW */
    ret = wc_MXC_MAA_init(length*sizeof(mp_digit)*8);
    if (ret != EXIT_SUCCESS){
        WOLFSSL_MSG("HW Init Failed");
        return ret;
    }

    /* Start Math And Cast to expect types for SDK */
    WOLFSSL_MSG("Starting Computation in MAA");
    ret = MXC_TPU_MAA_Compute(clc, (char *)(multipler->dp),
                                    (char *)(multiplicand->dp),
                                    (char *)(exp->dp), (char *)(mod->dp),
                                    (int *)(result_tmp_ptr->dp),
                                    (length*sizeof(mp_digit)));
    WOLFSSL_MSG("MAA Finished Computation");
    if(wc_MXC_error(&ret) != EXIT_SUCCESS){
        WOLFSSL_MSG("HW Computation Error");
        return ret;
    }

    ret = wc_MXC_MAA_Shutdown();
    if(ret != EXIT_SUCCESS){
        WOLFSSL_MSG("HW Shutdown Failure");
        return ret;
    }

    /* Copy tmp result if needed */
    if((multipler == result) || (multiplicand == result) ||
        (exp == result) || (mod == result)){
        mp_copy(result_tmp_ptr, result);
    }

    result->used = wc_MXC_MAA_adjustUsed(result->dp, length);
    return ret;
}



int wc_MXC_MAA_expmod(mp_int* base, mp_int* exp, mp_int* mod,
                            mp_int* result)
{
    mp_int multiplicand;
    multiplicand.dp[0] = 0x01;
    multiplicand.used = 1;
    WOLFSSL_MSG("Preparing exptmod MAA HW Call");
    return wc_MXC_MAA_math(base, &multiplicand, exp, mod, result,
                            WC_MXC_TPU_MAA_EXP);
}

int wc_MXC_MAA_sqrmod(mp_int* multipler, mp_int* mod, mp_int* result)
{
    mp_int multiplicand;
    multiplicand.dp[0] = 0x01;
    multiplicand.used = 1;
    WOLFSSL_MSG("Preparing sqrmod MAA HW Call");
    return wc_MXC_MAA_math(multipler, &multiplicand, NULL, mod, result,
                            WC_MXC_TPU_MAA_SQ);
}

int wc_MXC_MAA_mulmod(mp_int* multipler, mp_int* multiplicand, mp_int* mod,
                            mp_int* result)
{
    WOLFSSL_MSG("Preparing mulmod MAA HW Call");
    return wc_MXC_MAA_math(multipler, multiplicand, NULL, mod, result,
                            WC_MXC_TPU_MAA_MUL);
}

int wc_MXC_MAA_sqrmulmod(mp_int* multipler, mp_int* multiplicand,
                            mp_int* exp, mp_int* mod, mp_int* result)
{
    WOLFSSL_MSG("Preparing sqrmulmod MAA HW Call");
    return wc_MXC_MAA_math(multipler, multiplicand, NULL, mod, result,
                            WC_MXC_TPU_MAA_SQMUL);
}

int wc_MXC_MAA_addmod(mp_int* multipler, mp_int* multiplicand, mp_int* mod,
                            mp_int* result)
{
    WOLFSSL_MSG("Preparing addmod MAA HW Call");
    return wc_MXC_MAA_math(multipler, multiplicand, NULL, mod, result,
                            WC_MXC_TPU_MAA_ADD);
}

int wc_MXC_MAA_submod(mp_int* multipler, mp_int* multiplicand, mp_int* mod,
                            mp_int* result)
{
    WOLFSSL_MSG("Preparing submod MAA HW Call");
    if((mod->used < multipler->used) || (mod->used < multiplicand->used)){
            WOLFSSL_MSG("HW Limitation: Defaulting back to software");
            return mxc_submod(multipler, multiplicand, mod, result);
    }
    else{
        return wc_MXC_MAA_math(multipler, multiplicand, NULL, mod, result,
                             WC_MXC_TPU_MAA_SUB);
    }
}

/* General Function to call hardware control */
int hw_mulmod(mp_int* multiplier, mp_int* multiplicand, mp_int* mod,
                    mp_int* result)
{
    if ((multiplier->used == 0) || (multiplicand->used == 0)) {
        mp_zero(result);
        return EXIT_SUCCESS;
    }
    else{
        if(wc_MXC_MAA_Fallback(3, multiplier->used, mod->used,
                                multiplicand->used) != EXIT_SUCCESS){
                return mxc_mulmod(multiplier, multiplicand, mod, result);
        }
        else{
            return wc_MXC_MAA_mulmod(multiplier, multiplicand, mod, result);
        }
    }
}

int hw_addmod(mp_int* a, mp_int* b, mp_int* mod, mp_int* result)
{
    int err = MP_OKAY;
    /* Validate parameters. */
    if ((a == NULL) || (b == NULL) || (mod == NULL) || (result == NULL)) {
        err = MP_VAL;
    }
    if (err == MP_OKAY) {
        if(wc_MXC_MAA_Fallback(3, a->used, b->used, mod->used) != EXIT_SUCCESS){
            err = mxc_addmod(a, b, mod, result);
        }
        else{
            err = wc_MXC_MAA_addmod(a, b, mod, result);
        }
    }
}


int hw_submod(mp_int* a, mp_int* b, mp_int* mod, mp_int* result)
{
    int err = MP_OKAY;
    /* Validate parameters. */
    if ((a == NULL) || (b == NULL) || (mod == NULL) || (result == NULL)) {
        err = MP_VAL;
    }
    if (err == MP_OKAY) {
        if(wc_MXC_MAA_Fallback(3, a->used, b->used, mod->used) != EXIT_SUCCESS){
            err = mxc_submod(a, b, mod, result);
        }
        else{
            err = wc_MXC_MAA_submod(a, b, mod, result);
        }
    }
    return err;
}

int hw_exptmod(mp_int* base, mp_int* exp, mp_int* mod, mp_int* result)
{
    int err = MP_OKAY;
    /* Validate parameters. */
    if ((base == NULL) || (exp == NULL) || (mod == NULL) || (result == NULL)){
        err = MP_VAL;
    }
    if (err == MP_OKAY) {
        if((mod->used < exp->used) || (mod->used < base->used)){
            err = mxc_exptmod(base, exp, mod, result);
        }
        else if(wc_MXC_MAA_Fallback(3, base->used, exp->used, mod->used)
                    != EXIT_SUCCESS){
            return mxc_exptmod(base, exp, mod, result);
        }
        else{
            err = wc_MXC_MAA_expmod(base, exp, mod, result);
        }
    }
    return err;
}


/* No mod function avaliable with hardware, however preform a submod    */
/* (a - 0) mod m will essentially preform the same operation as a mod m */
int hw_mod(mp_int* a, mp_int* mod, mp_int* result)
{
    if(wc_MXC_MAA_Fallback(2, a->used, mod->used)
        != EXIT_SUCCESS){
        return mxc_mod(a, mod, result);
    }
    else{
        mp_int b;
        b.dp[0] = 0x00;
        b.used = 0x01;
        return hw_submod(a, &b, mod, result);
    }
}

int hw_sqrmod(mp_int* base, mp_int* mod, mp_int* result)
{
        if (base->used == 0) {
        mp_zero(result);
        return EXIT_SUCCESS;
    }
    else{
        return wc_MXC_MAA_sqrmod(base, mod, result);
    }

}

#endif


#if defined(MAX3266X_RTC)
/* Initialize the RTC */
int wc_MXC_RTC_Init(void)
{
    /* RTC Init for benchmark */
    if (MXC_RTC_Init(0, 0) != E_NO_ERROR) {
        return WC_HW_E;
    }

    /* Disable the Interrupt */
    if (MXC_RTC_DisableInt(MXC_RTC_INT_EN_LONG) == E_BUSY) {
        return WC_HW_E;
    }

    if (MXC_RTC_SquareWaveStart(MXC_RTC_F_512HZ) == E_BUSY) {
        return E_BUSY;
    }

    if (MXC_RTC_Start() != E_NO_ERROR){
        return WC_HW_E;
    }

    return 0;
}

/* Reset the RTC */
int wc_MXC_RTC_Reset(void)
{
    if (MXC_RTC_Stop() != E_NO_ERROR){
        return WC_HW_E;
    }
    if (wc_MXC_RTC_Init() != E_NO_ERROR){
        return WC_HW_E;
    }
    return 0;
}

/* Function to handle RTC read retries */
void wc_MXC_RTC_GetRTCValue(int32_t (*rtcGetFunction)(uint32_t*),
                                uint32_t* outValue, int32_t* err) {
    *err = rtcGetFunction(outValue);  /* Initial attempt to get the value */
    while (*err != E_NO_ERROR) {
        *err = rtcGetFunction(outValue);  /* Retry if the error persists */
    }
}

/* Function to provide the current time as a double */
double wc_MXC_RTC_Time(void) {
    int32_t err;
    uint32_t rtc_seconds, rtc_subseconds;

    /* Retrieve sub-seconds from RTC */
    wc_MXC_RTC_GetRTCValue((int32_t (*)(uint32_t*))MXC_RTC_GetSubSeconds, \
                                    &rtc_subseconds, &err);
    if (err != E_NO_ERROR){
        return (double)err;
    }
    /* Retrieve seconds from RTC */
    wc_MXC_RTC_GetRTCValue((int32_t (*)(uint32_t*))MXC_RTC_GetSeconds, \
                                &rtc_seconds, &err);
    if (err != E_NO_ERROR){
        return (double)err;
    }
    return ((double)rtc_seconds + ((double)rtc_subseconds / 4096));
}

#endif /* MAX3266X_RTC */


#endif /* WOLFSSL_MAX32665 || WOLFSSL_MAX32666 */