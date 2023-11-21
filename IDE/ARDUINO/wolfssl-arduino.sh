#!/bin/sh

# this script will reformat the wolfSSL source code to be compatible with
# an Arduino project
# run as bash ./wolfssl-arduino.sh

DIR=${PWD##*/}

if [ "$DIR" = "ARDUINO" ]; then
	if [ ! -d "wolfSSL" ]; then
	    mkdir wolfSSL
    fi

    cp ../../src/*.c ./wolfSSL
    cp ../../wolfcrypt/src/*.c ./wolfSSL

    if [ ! -d "wolfSSL/wolfssl" ]; then
	    mkdir wolfSSL/wolfssl
    fi
    cp ../../wolfssl/*.h ./wolfSSL/wolfssl
    if [ ! -d "wolfSSL/wolfssl/wolfcrypt" ]; then
        mkdir wolfSSL/wolfssl/wolfcrypt
    fi
    cp ../../wolfssl/wolfcrypt/*.h ./wolfSSL/wolfssl/wolfcrypt

    # support misc.c as include in wolfcrypt/src
    if [ ! -d "./wolfSSL/wolfcrypt" ]; then
        mkdir ./wolfSSL/wolfcrypt
    fi
    if [ ! -d "./wolfSSL/wolfcrypt/src" ]; then
        mkdir ./wolfSSL/wolfcrypt/src
    fi
    cp ../../wolfcrypt/src/misc.c ./wolfSSL/wolfcrypt/src
    cp ../../wolfcrypt/src/asm.c  ./wolfSSL/wolfcrypt/src
    
    # support ssl_misc as include in src
    if [ ! -d "./wolfSSL/src" ]; then
	mkdir ./wolfSSL/src
    fi
    cp ../../src/*.c ./wolfSSL/src/

    # put bio and evp as includes
    mv ./wolfSSL/bio.c ./wolfSSL/wolfssl
    mv ./wolfSSL/evp.c ./wolfSSL/wolfssl

    # make a copy of evp.c and bio.c for ssl.c to include inline
    cp ./wolfSSL/wolfssl/evp.c ./wolfSSL/wolfcrypt/src/evp.c
    cp ./wolfSSL/wolfssl/bio.c ./wolfSSL/wolfcrypt/src/bio.c
    
    # copy openssl compatibility headers to their appropriate location
    if [ ! -d "./wolfSSL/wolfssl/openssl" ]; then
        mkdir ./wolfSSL/wolfssl/openssl
    fi
    cp ../../wolfssl/openssl/* ./wolfSSL/wolfssl/openssl


    cat > ./wolfSSL/wolfssl.h <<EOF
/* Generated wolfSSL header file for Arduino */
#include <user_settings.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
EOF


# Creates user_settings file if one does not exist
    if [ ! -f "./wolfSSL/user_settings.h" ]; then
	cat > ./wolfSSL/user_settings.h <<EOF
/* Generated wolfSSL user_settings.h file for Arduino */
#ifndef ARDUINO_USER_SETTINGS_H
#define ARDUINO_USER_SETTINGS_H

/* Platform */
#define WOLFSSL_ARDUINO

/* Math library (remove this to use normal math)*/
#define USE_FAST_MATH
#define TFM_NO_ASM

/* RNG DEFAULT !!FOR TESTING ONLY!! */
/* comment out the error below to get started w/ bad entropy source
 * This will need fixed before distribution but is OK to test with */
#error "needs solved, see: https://www.wolfssl.com/docs/porting-guide/"
#define WOLFSSL_GENSEED_FORTEST

#endif /* ARDUINO_USER_SETTINGS_H */
EOF
    fi

    cp wolfSSL/wolfssl/wolfcrypt/settings.h wolfSSL/wolfssl/wolfcrypt/settings.h.bak
    cat > ./wolfSSL/wolfssl/wolfcrypt/settings.h <<EOF
/*wolfSSL Generated ARDUINO settings */
#ifndef WOLFSSL_USER_SETTINGS
    #define WOLFSSL_USER_SETTINGS
#endif /* WOLFSSL_USER_SETTINGS */ 
/*wolfSSL Generated ARDUINO settings: END */	

EOF
    cat ./wolfSSL/wolfssl/wolfcrypt/settings.h.bak >> ./wolfSSL/wolfssl/wolfcrypt/settings.h

else
    echo "ERROR: You must be in the IDE/ARDUINO directory to run this script"
fi
