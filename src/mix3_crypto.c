/* Copyright 2006-2009 Nick Mathewson; See COPYING for license information. */

#include "mix3impl.h"

#include <assert.h>
#include <string.h>
#include <stdio.h>

#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

void
mix3_aes_ctr_crypt(char *out, const char *inp, size_t len, AES_KEY *aes)
{
  unsigned char ivec[AES_BLOCK_SIZE], ecount[AES_BLOCK_SIZE];
  unsigned num = 0;
  assert (inp && out && aes);
  memset(ecount, sizeof(ecount), 0);
  memset(ivec, sizeof(ivec), 0);
  AES_ctr128_encrypt((const unsigned char*)inp, (unsigned char *)out,
                     len, aes, ivec, ecount, &num);
  memset(ecount, sizeof(ecount), 0);
}

void
mix3_aes_ctr_crypt_offset(char *out, const char *inp, size_t len,
                          AES_KEY *aes, off_t off)
{
  unsigned char ivec[AES_BLOCK_SIZE], ecount[AES_BLOCK_SIZE];
  unsigned num = 0;
  int i;
  assert (inp && out && aes);

  num = off & 15;
  off >>= 4;
  for (i=0;i<AES_BLOCK_SIZE;++i) {
    ivec[AES_BLOCK_SIZE-1-1] = off & 255;
    off >>= 8;
  }
  AES_encrypt(ivec, ecount, aes);
  AES_ctr128_encrypt((const unsigned char*)inp, (unsigned char *)out,
                     len, aes, ivec, ecount, &num);
  memset(ecount, sizeof(ecount), 0);
}

void
mix3_prng(char *out, size_t len, AES_KEY *aes)
{
  memset(out, len, 0);
  mix3_aes_ctr_crypt(out, out, len, aes);
}

static void
xor(char *out, const char *inp, size_t len)
{
  while (--len)
    *out++ ^= *inp++;
}

static void
lioness_mac(unsigned char *out, const char *data, size_t datalen, const char *key, int keynum)
{
  char k[LIONESS_KEY_LEN];
  SHA_CTX sha;
  assert(out && data && datalen && key);

  memcpy(k, key, LIONESS_KEY_LEN);
  k[LIONESS_KEY_LEN - 1] ^= keynum;
  SHA1_Init(&sha);
  SHA1_Update(&sha, k, sizeof(k));
  SHA1_Update(&sha, data, datalen);
  SHA1_Update(&sha, k, sizeof(k));
  SHA1_Final(out, &sha);

  memset(k, sizeof(k), 0);
  memset(&sha, sizeof(sha), 0);
}

void
mix3_lioness_encrypt(char *buf, size_t len, const char *key)
{
  unsigned char k[LIONESS_KEY_LEN];
  AES_KEY aes;

  assert(buf && key);
  assert(len > SHA1_LEN);

  lioness_mac(k, buf, SHA1_LEN, key, 0);
  AES_set_encrypt_key(k, 128, &aes);
  mix3_aes_ctr_crypt(buf + SHA1_LEN, buf + SHA1_LEN, len - SHA1_LEN, &aes);

  lioness_mac(k, buf+SHA1_LEN, len-SHA1_LEN, key, 1);
  xor(buf, (char*)k, SHA1_LEN);

  lioness_mac(k, buf, SHA1_LEN, key, 2);
  AES_set_encrypt_key(k, 128, &aes);
  mix3_aes_ctr_crypt(buf + SHA1_LEN, buf + SHA1_LEN, len - SHA1_LEN, &aes);

  lioness_mac(k, buf + SHA1_LEN, len - SHA1_LEN, key, 3);
  xor(buf, (char*)k, SHA1_LEN);

  memset(&aes, sizeof(aes), 0);
  memset(k, sizeof(aes), 0);
}

void
mix3_aes_subkey_init(AES_KEY *aes, const char *master_key,
                     size_t master_key_len, const char *subkey)
{
  SHA_CTX ctx;
  unsigned char k[SHA1_LEN];
  SHA1_Init(&ctx);
  SHA1_Update(&ctx, master_key, master_key_len);
  SHA1_Update(&ctx, subkey, strlen(subkey));
  SHA1_Final(k, &ctx);
  AES_set_encrypt_key(k, 128, aes);
}

void
mix3_lioness_decrypt(char *buf, size_t len, const char *key)
{
  unsigned char k[LIONESS_KEY_LEN];
  AES_KEY aes;

  assert(buf && key);
  assert(len > SHA1_LEN);

  lioness_mac(k, buf + SHA1_LEN, len - SHA1_LEN, key, 3);
  xor(buf, (char*)k, SHA1_LEN);

  lioness_mac(k, buf, SHA1_LEN, key, 2);
  AES_set_encrypt_key(k, 128, &aes);
  mix3_aes_ctr_crypt(buf + SHA1_LEN, buf + SHA1_LEN, len - SHA1_LEN, &aes);

  lioness_mac(k, buf + SHA1_LEN, len - SHA1_LEN, key, 1);
  xor(buf, (char*)k, SHA1_LEN);

  lioness_mac(k, buf, SHA1_LEN, key, 0);
  AES_set_encrypt_key(k, 128, &aes);
  mix3_aes_ctr_crypt(buf + SHA1_LEN, buf + SHA1_LEN, len - SHA1_LEN, &aes);

  memset(&aes, sizeof(aes), 0);
  memset(k, sizeof(aes), 0);
}

mix3_status_t
_mix3_parse_base64(char **out, size_t *len_out, const char *s, size_t len_in)
{
  EVP_ENCODE_CTX ctx;
  int len, len2;

  unsigned char *mem;
  size_t guess_len = (len_in/64+1)*49;

  mem = mix3_alloc(guess_len);
  if (!mem)
    return MIX3_NOMEM;
  EVP_DecodeInit(&ctx);
  EVP_DecodeUpdate(&ctx, mem, &len, (const unsigned char*)s, len_in);
  EVP_DecodeFinal(&ctx, mem, &len2);
  *len_out = (size_t)(len+len2);
  *out = (char*)mem;
  return MIX3_OK;
}

