#pragma once

#include "./common.h"

// SHA256 outputs a 32 byte digest, uses 64 byte blocks
#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32

typedef struct {
    byte data[SHA256_BLOCK_SIZE];
    word datalen;
    unsigned long long bitlen;
    word state[8];
} sha256_ctx;

typedef struct {
    sha256_ctx ctx_inside;
    sha256_ctx ctx_outside;

    byte block_ipad[SHA256_BLOCK_SIZE];
    byte block_opad[SHA256_BLOCK_SIZE];
} hmac_sha256_ctx;

void sha256_init(sha256_ctx *ctx);
void sha256_update(sha256_ctx *ctx, const byte *data, size_t dlen);
void sha256_final(sha256_ctx *ctx, byte output[SHA256_DIGEST_SIZE]);

void hmac_sha256_init(hmac_sha256_ctx *octx, const byte *key, unsigned int key_size);
void hmac_sha256_update(hmac_sha256_ctx *octx, const byte *message, unsigned int message_len);
void hmac_sha256_final(hmac_sha256_ctx *octx, byte *mac);