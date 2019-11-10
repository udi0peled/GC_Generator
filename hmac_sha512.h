#pragma once

#include "./common.h"

//SHA-512 block size
#define SHA512_BLOCK_SIZE 128
//SHA-512 digest size
#define SHA512_DIGEST_SIZE 64
//Minimum length of the padding string
#define SHA512_MIN_PAD_SIZE 17


/*
 * SHA-512 context structure
 */

typedef struct {
    dword state[8];                 /*!< intermediate digest state  */
    byte buffer[SHA512_BLOCK_SIZE]; /*!< data block being processed */
    unsigned int datalen;
    unsigned long long bitlen;
} sha512_ctx;

typedef struct {
    sha512_ctx ctx_inside;
    sha512_ctx ctx_outside;

    byte block_ipad[SHA512_BLOCK_SIZE];
    byte block_opad[SHA512_BLOCK_SIZE];
} hmac_sha512_ctx;

void sha512_init(sha512_ctx *ctx);
void sha512_update(sha512_ctx *ctx, const byte *data, unsigned int dlen);
void sha512_final(sha512_ctx *ctx, byte output[SHA512_DIGEST_SIZE]);

void hmac_sha512_init(hmac_sha512_ctx *octx, const byte *key, unsigned int key_size);
void hmac_sha512_update(hmac_sha512_ctx *octx, const byte *message, unsigned int message_len);
void hmac_sha512_final(hmac_sha512_ctx *octx, byte *mac);
