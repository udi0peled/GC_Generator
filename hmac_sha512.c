/*
 * sha512.c - mbed TLS (formerly known as PolarSSL) implementation of SHA512
 *
 * Modifications Copyright 2017 Google Inc.
 * Modifications Author: Joe Richey (joerichey@google.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
/*
 *  FIPS-180-2 compliant SHA-512 implementation
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
/*
 *  The SHA-512 Secure Hash Standard was published by NIST in 2002.
 *
 *  http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf
 */

#include "./hmac_sha512.h"
#include <stdio.h>

#define SHR(x, n) (x >> n)
#define ROTR(x, n) (SHR(x, n) | (x << (64 - n)))

#define S0(x) (ROTR(x, 1) ^ ROTR(x, 8) ^ SHR(x, 7))
#define S1(x) (ROTR(x, 19) ^ ROTR(x, 61) ^ SHR(x, 6))

#define S2(x) (ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39))
#define S3(x) (ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41))

#define F0(x, y, z) ((x & y) | (z & (x | y)))
#define F1(x, y, z) (z ^ (x & (y ^ z)))

/*
 * Round constants
 */
static const dword K[80] = {
    0x428A2F98D728AE22, 0x7137449123EF65CD,
    0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
    0x3956C25BF348B538, 0x59F111F1B605D019,
    0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
    0xD807AA98A3030242, 0x12835B0145706FBE,
    0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
    0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1,
    0x9BDC06A725C71235, 0xC19BF174CF692694,
    0xE49B69C19EF14AD2, 0xEFBE4786384F25E3,
    0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
    0x2DE92C6F592B0275, 0x4A7484AA6EA6E483,
    0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
    0x983E5152EE66DFAB, 0xA831C66D2DB43210,
    0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
    0xC6E00BF33DA88FC2, 0xD5A79147930AA725,
    0x06CA6351E003826F, 0x142929670A0E6E70,
    0x27B70A8546D22FFC, 0x2E1B21385C26C926,
    0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
    0x650A73548BAF63DE, 0x766A0ABB3C77B2A8,
    0x81C2C92E47EDAEE6, 0x92722C851482353B,
    0xA2BFE8A14CF10364, 0xA81A664BBC423001,
    0xC24B8B70D0F89791, 0xC76C51A30654BE30,
    0xD192E819D6EF5218, 0xD69906245565A910,
    0xF40E35855771202A, 0x106AA07032BBD1B8,
    0x19A4C116B8D2D0C8, 0x1E376C085141AB53,
    0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8,
    0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB,
    0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
    0x748F82EE5DEFB2FC, 0x78A5636F43172F60,
    0x84C87814A1F0AB72, 0x8CC702081A6439EC,
    0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9,
    0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
    0xCA273ECEEA26619C, 0xD186B8C721C0C207,
    0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
    0x06F067AA72176FBA, 0x0A637DC5A2C898A6,
    0x113F9804BEF90DAE, 0x1B710B35131C471B,
    0x28DB77F523047D84, 0x32CAAB7B40C72493,
    0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
    0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A,
    0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817
};

void sha512_process(sha512_ctx *ctx, const byte data[128]) {
  int i;
  dword temp1, temp2, W[80];
  dword A, B, C, D, E, F, G, H;

#define P(a, b, c, d, e, f, g, h, x, K)    \
  {                                          \
    temp1 = h + S3(e) + F1(e, f, g) + K + x; \
    temp2 = S2(a) + F0(a, b, c);             \
    d += temp1;                              \
    h = temp1 + temp2;                       \
  }


  /*
  * 64-bit integer manipulation macros (big endian)
  */
#ifndef GET_DWORD_BE
#define GET_DWORD_BE(n, b, i)                                           \
    {                                                                   \
      (n) = ((dword)(b)[(i)] << 56) | ((dword)(b)[(i) + 1] << 48) |     \
            ((dword)(b)[(i) + 2] << 40) | ((dword)(b)[(i) + 3] << 32) | \
            ((dword)(b)[(i) + 4] << 24) | ((dword)(b)[(i) + 5] << 16) | \
            ((dword)(b)[(i) + 6] << 8) | ((dword)(b)[(i) + 7]);         \
    }
#endif /* GET_DWORD_BE */

  for (i = 0; i < 16; i++) {
    GET_DWORD_BE(W[i], data, i << 3);
  }

  for (; i < 80; i++) {
    W[i] = S1(W[i - 2]) + W[i - 7] + S0(W[i - 15]) + W[i - 16];
  }

  A = ctx->state[0];
  B = ctx->state[1];
  C = ctx->state[2];
  D = ctx->state[3];
  E = ctx->state[4];
  F = ctx->state[5];
  G = ctx->state[6];
  H = ctx->state[7];
  i = 0;

  do {
    P(A, B, C, D, E, F, G, H, W[i], K[i]);
    i++;
    P(H, A, B, C, D, E, F, G, W[i], K[i]);
    i++;
    P(G, H, A, B, C, D, E, F, W[i], K[i]);
    i++;
    P(F, G, H, A, B, C, D, E, W[i], K[i]);
    i++;
    P(E, F, G, H, A, B, C, D, W[i], K[i]);
    i++;
    P(D, E, F, G, H, A, B, C, W[i], K[i]);
    i++;
    P(C, D, E, F, G, H, A, B, W[i], K[i]);
    i++;
    P(B, C, D, E, F, G, H, A, W[i], K[i]);
    i++;
  } while (i < 80);

  ctx->state[0] += A;
  ctx->state[1] += B;
  ctx->state[2] += C;
  ctx->state[3] += D;
  ctx->state[4] += E;
  ctx->state[5] += F;
  ctx->state[6] += G;
  ctx->state[7] += H;
}


void sha512_init(sha512_ctx *ctx) {
  ctx->bitlen = 0;
  ctx->datalen = 0;

  ctx->state[0] = 0x6A09E667F3BCC908;
  ctx->state[1] = 0xBB67AE8584CAA73B;
  ctx->state[2] = 0x3C6EF372FE94F82B;
  ctx->state[3] = 0xA54FF53A5F1D36F1;
  ctx->state[4] = 0x510E527FADE682D1;
  ctx->state[5] = 0x9B05688C2B3E6C1F;
  ctx->state[6] = 0x1F83D9ABFB41BD6B;
  ctx->state[7] = 0x5BE0CD19137E2179;

  for (int i=0; i< SHA512_BLOCK_SIZE; i++) {
    ctx->buffer[i] = 0x00;
  }
}

/*
 * SHA-512 process buffer
 */
void sha512_update(sha512_ctx *ctx, const byte *data, unsigned int dlen) {
  unsigned int fill;
  unsigned int left;

  if (dlen == 0) return;

  left = (unsigned int)(ctx->bitlen & 0x7F);
  fill = 128 - left;

  ctx->bitlen += dlen;

  if (ctx->bitlen < dlen) ctx->datalen++;

  if (left && dlen >= fill) {
    for (int i = 0; i < fill; i++) {
      ctx->buffer[left + i] = data[i];
    }
    sha512_process(ctx, ctx->buffer);
    data += fill;
    dlen -= fill;
    left = 0;
  }

  while (dlen >= 128) {
    sha512_process(ctx, data);
    data += 128;
    dlen -= 128;
  }

  for (int i = 0; i < dlen; i++) {
    ctx->buffer[left + i] = data[i];
  }
}

static const byte sha512_padding[128] = {
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/*
 * SHA-512 final digest
 */
void sha512_final(sha512_ctx *ctx, byte output[SHA512_DIGEST_SIZE]) {
  unsigned int last, padn;
  unsigned long high, low;
  byte msglen[16];

  high = (ctx->bitlen >> 61) | (ctx->datalen << 3);
  low = (ctx->bitlen << 3);

#ifndef PUT_DWORD_BE
#define PUT_DWORD_BE(n, b, i)           \
    {                                   \
      (b)[(i)] = (byte)((n) >> 56);     \
      (b)[(i) + 1] = (byte)((n) >> 48); \
      (b)[(i) + 2] = (byte)((n) >> 40); \
      (b)[(i) + 3] = (byte)((n) >> 32); \
      (b)[(i) + 4] = (byte)((n) >> 24); \
      (b)[(i) + 5] = (byte)((n) >> 16); \
      (b)[(i) + 6] = (byte)((n) >> 8);  \
      (b)[(i) + 7] = (byte)((n));       \
    }
#endif /* PUT_DWORD_BE */

  PUT_DWORD_BE(high, msglen, 0);
  PUT_DWORD_BE(low, msglen, 8);

  last = (unsigned int)(ctx->bitlen & 0x7F);
  padn = (last < 112) ? (112 - last) : (240 - last);

  sha512_update(ctx, sha512_padding, padn);
  sha512_update(ctx, msglen, 16);

  PUT_DWORD_BE(ctx->state[0], output, 0);
  PUT_DWORD_BE(ctx->state[1], output, 8);
  PUT_DWORD_BE(ctx->state[2], output, 16);
  PUT_DWORD_BE(ctx->state[3], output, 24);
  PUT_DWORD_BE(ctx->state[4], output, 32);
  PUT_DWORD_BE(ctx->state[5], output, 40);
  PUT_DWORD_BE(ctx->state[6], output, 48);
  PUT_DWORD_BE(ctx->state[7], output, 56);
}

/*********************** HMAC-SHA512 FUNCTION DEFINITIONS ***********************/

void hmac_sha512_init(hmac_sha512_ctx *ctx, const byte *key, unsigned int key_size)
{
  //unsigned int fill;
  unsigned int num;

  byte *key_used;
  unsigned char key_temp[SHA512_DIGEST_SIZE];
  int i;

  if (key_size == SHA512_BLOCK_SIZE) {
    key_used = (byte*) key;
    num = SHA512_BLOCK_SIZE;
  } else {
    if (key_size > SHA512_BLOCK_SIZE){
      num = SHA512_DIGEST_SIZE;
      sha512_ctx ctx;
      sha512_init(&ctx);
      sha512_update(&ctx, key, key_size);
      sha512_final(&ctx, key_temp);
      key_used = key_temp;
    } else { /* key_size > SHA512_BLOCK_SIZE */
      key_used = (byte*) key;
      num = key_size;
    }
    //fill = SHA512_BLOCK_SIZE - num;
    //memset(ctx->block_ipad + num, 0x36, fill);
    //memset(ctx->block_opad + num, 0x5c, fill);

    for (int i=num; i<SHA512_BLOCK_SIZE; i++) {
      ctx->block_ipad[i] = 0x36;
      ctx->block_opad[i] = 0x5c;
    }
  }

  for (i = 0; i < (int) num; i++) {
    ctx->block_ipad[i] = key_used[i] ^ 0x36;
    ctx->block_opad[i] = key_used[i] ^ 0x5c;
  }

  sha512_init(&ctx->ctx_inside);
  sha512_update(&ctx->ctx_inside, ctx->block_ipad, SHA512_BLOCK_SIZE);

  sha512_init(&ctx->ctx_outside);
  sha512_update(&ctx->ctx_outside, ctx->block_opad, SHA512_BLOCK_SIZE);
}

void hmac_sha512_update(hmac_sha512_ctx *ctx, const byte *message, unsigned int message_len)
{
  sha512_update(&ctx->ctx_inside, message, message_len);
}

void hmac_sha512_final(hmac_sha512_ctx *ctx, byte *mac)
{
  byte digest_inside[SHA512_DIGEST_SIZE];
  byte mac_temp[SHA512_DIGEST_SIZE];

  sha512_final(&ctx->ctx_inside, digest_inside);
  sha512_update(&ctx->ctx_outside, digest_inside, SHA512_DIGEST_SIZE);
  sha512_final(&ctx->ctx_outside, mac);
}