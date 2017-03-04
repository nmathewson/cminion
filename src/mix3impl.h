/* Copyright 2006-2009 Nick Mathewson; See COPYING for license information. */

#ifndef _MIX3IMPL_H
#define _MIX3IMPL_H

#include <sys/types.h>
#include <openssl/aes.h>
#include "mix3.h"

/* memory */
void *mix3_alloc(size_t n);
void *mix3_realloc(void *ptr, size_t n);
void mix3_free(void *ptr);
char *mix3_strndup(const char *s, size_t n);
void *mix3_memdup(const void *s, size_t n);
void *mix3_alloc_zero(size_t n);
#define MIX3_NEW(tp) (mix3_alloc_zero(sizeof(tp)))

/* base64 */
mix3_status_t _mix3_parse_base64(char **out, size_t *len_out, const char *s,
                                 size_t len_in);

/* crypto. */
#define LIONESS_KEY_LEN 20
#define SHA1_LEN 20
#define AES_KEY_LEN 16

void mix3_aes_ctr_crypt(char *out, const char *inp, size_t len, AES_KEY *aes);
void mix3_aes_ctr_crypt_offset(char *out, const char *inp, size_t len,
                               AES_KEY *aes, off_t off);
void mix3_prng(char *out, size_t len, AES_KEY *aes);
void mix3_lioness_encrypt(char *buf, size_t len, const char *key);
void mix3_aes_subkey_init(AES_KEY *aes, const char *master_key,
                          size_t master_key_len, const char *subkey);
void mix3_lioness_decrypt(char *buf, size_t len, const char *key);
void mix3_rsa_oaep_enc(char *out, const char *in, size_t in_len, RSA *pk);
int mix3_rsa_oaep_dec(char *out, size_t out_len,
                      const char *in, size_t in_len, RSA *pk);

/* desc */

typedef struct mix3_routing_info_t {
  uint16_t routing_type;
  char *routing_info;
  uint16_t len;
  RSA *pk;
} mix3_routing_info_t;



/* inlines */
extern inline uint16_t GET_U16(const char *p);
extern inline void SET_U16(char *p, uint16_t u);


extern inline uint16_t
GET_U16(const char *p)
{
  uint16_t r;
  r = (unsigned)((uint8_t)(p[0])) << 8;
  r += (uint8_t)(p[0]);
  return r;
}
extern inline void
SET_U16(char *p, uint16_t u)
{
  p[0] = u >> 8;
  p[1] = u & 255;
}

#endif

