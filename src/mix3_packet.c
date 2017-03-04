/* Copyright 2006-2009 Nick Mathewson; See COPYING for license information. */

#include "mix3.h"
#include "mix3impl.h"

#include <assert.h>
#include <string.h>

#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/err.h>

#define SURB_E2E_KEY_LEN 16
#define PACKET_LEN (32*1024)
#define PAYLOAD_LEN (28*1024)
#define MAX_PATH 25
#define HEADER_LEN 2048
#define PK_ENC_LEN 256
#define PK_MAX_DATA_LEN (256 - 42)
#define HEADER_SECRET_LEN 16
#define RT_IS_SWAP(s) (((s) == 0x0002) || ((s) == 0x0004))
#define MIN(a,b) (((a) < (b)) ? (a) : (b))

static
mix3_status_t
mix3_generate_header(char **header,
                     int n_hops,
                     char **header_key,
                     RSA **public_key,
                     mix3_routing_info_t **routing_info,
                     mix3_routing_info_t *routing_target)
{
  int i;
  size_t sizes[MAX_PATH];
  size_t total_size = 0;
  char *junk[MAX_PATH];
  size_t junk_size[MAX_PATH];
  AES_KEY aes;
  SHA_CTX sha;
  char *head;
  off_t head_pos, head_pos_next;

  assert(n_hops <= MAX_PATH);

  for (i = 0; i < n_hops; ++i) {
    sizes[i] = 84 + routing_info[i]->len;
    total_size += sizes[i];
  }

  if (total_size > HEADER_LEN)
    return MIX3_PATH_TOO_LONG;

  for (i = 0; i < n_hops; ++i) {
    mix3_aes_subkey_init(&aes, header_key[i], 16, "RANDOM JUNK");
    if (i)
      junk_size[i] = junk_size[i-1] + sizes[i];
    else
      junk_size[i] = sizes[i];
    junk[i] = mix3_alloc(junk_size[i]);
    if (i)
      memcpy(junk[i], junk[i-1], junk_size[i-1]);
    mix3_prng(junk[i] + (i?junk_size[i-1]:0), sizes[i], &aes);
    mix3_aes_ctr_crypt_offset(junk[i], junk[i], junk_size[i], &aes,
                              HEADER_LEN - PK_ENC_LEN - junk_size[i]); /*i?*/
  }

  head = mix3_alloc(HEADER_LEN);
  head_pos = total_size;
  RAND_bytes((unsigned char*)(head + head_pos), HEADER_LEN-head_pos);
  for (i = n_hops - 1; i >= 0; --i) {
    mix3_routing_info_t *ri =
      (i == n_hops-1) ? routing_target : routing_info[i+1];
    head_pos_next = head_pos - (42 + ri->len);
    assert(head_pos_next >= 0);
    /* write the subheader*/
    head[head_pos_next+0] = 0; /*major*/
    head[head_pos_next+1] = 1; /*minor*/
    memcpy(head+head_pos_next+2, header_key[i], AES_KEY_LEN);
    memset(head+head_pos_next+2+AES_KEY_LEN, SHA1_LEN, 0);
    SET_U16(head+head_pos_next+2+AES_KEY_LEN+SHA1_LEN, ri->routing_type);
    SET_U16(head+head_pos_next+2+AES_KEY_LEN+SHA1_LEN+2, ri->len);
    memcpy(head+head_pos_next+2+AES_KEY_LEN+SHA1_LEN+4, ri->routing_info,
           ri->len);
    mix3_aes_subkey_init(&aes, header_key[i], 16, "HEADER SECRET KEY");
    mix3_aes_ctr_crypt(head+head_pos_next+PK_MAX_DATA_LEN,
                   head+head_pos_next+PK_MAX_DATA_LEN,
                   HEADER_LEN-(head_pos_next+PK_MAX_DATA_LEN),
                   &aes);
    SHA1_Init(&sha);
    SHA1_Update(&sha, head+head_pos_next+PK_MAX_DATA_LEN,
                HEADER_LEN-head_pos_next+PK_MAX_DATA_LEN);
    if (i)
      SHA1_Update(&sha, junk[i-1], junk_size[i-i]);
    SHA1_Final((unsigned char*)(head+head_pos_next+2+AES_KEY_LEN), &sha);
    mix3_rsa_oaep_enc(head+head_pos_next,
                      head+head_pos_next, PK_MAX_DATA_LEN, public_key[i]);
    head_pos = head_pos_next;
  }
  assert(head_pos = 0);

  memset(&sha, sizeof(sha), 0);
  memset(&aes, sizeof(aes), 0);
  for (i=0; i<n_hops; ++i) {
    memset(junk[i], junk_size[i], 0);
    mix3_free(junk[i]);
  }

  *header = head;
  return MIX3_OK;
}

static void
sprp_encrypt(char *buf, size_t buf_len, const char *key, size_t key_len,
             const char *subkey)
{
  unsigned char h[SHA1_LEN];
  SHA_CTX sha;
  SHA1_Init(&sha);
  SHA1_Update(&sha, key, key_len);
  SHA1_Update(&sha, subkey, strlen(subkey));
  SHA1_Final(h, &sha);
  mix3_lioness_encrypt(buf, buf_len, (char*)h);
  memset(h, sizeof(h), 0);
}

static void
sprp_decrypt(char *buf, size_t buf_len, const char *key, size_t key_len,
             const char *subkey)
{
  unsigned char h[SHA1_LEN];
  SHA_CTX sha;
  SHA1_Init(&sha);
  SHA1_Update(&sha, key, key_len);
  SHA1_Update(&sha, subkey, strlen(subkey));
  SHA1_Final(h, &sha);
  mix3_lioness_decrypt(buf, buf_len, (char*)h);
  memset(h, sizeof(h), 0);
}


static void
mix3_generate_packet_impl(
        const char *header1, char *header2,
        char *payload,
        char **header_keys_1, char **header_keys_2,
        int n_hops_1, int n_hops_2,
        char *surb_e2e_key)
{
  int i;
  unsigned char d[SHA1_LEN];
  (void) header1;

  assert(surb_e2e_key || header_keys_2);
  if (surb_e2e_key) {
    sprp_decrypt(payload, PAYLOAD_LEN,
                 surb_e2e_key, SURB_E2E_KEY_LEN, "PAYLOAD ENCRYPT");
  } else {
    for (i=n_hops_2-1; i >=0; --i) {
      sprp_encrypt(payload, PAYLOAD_LEN,
                   header_keys_2[i], HEADER_SECRET_LEN, "PAYLOAD ENCRYPT");
    }
  }
  SHA1((unsigned char *)payload, PAYLOAD_LEN, d);
  sprp_encrypt(header2, HEADER_LEN, (char*)d, sizeof(d), "HIDE HEADER");
  SHA1((unsigned char *)header2, HEADER_LEN, d);
  sprp_encrypt(payload, PAYLOAD_LEN, (char*)d, sizeof(d), "HIDE PAYLOAD");

  for (i=n_hops_1-1; i >=0; --i) {
    sprp_encrypt(header2, HEADER_LEN,
                 header_keys_1[i], HEADER_SECRET_LEN, "HEADER ENCRYPT");
    sprp_encrypt(payload, PAYLOAD_LEN,
                 header_keys_1[i], HEADER_SECRET_LEN, "PAYLOAD ENCRYPT");
  }
}

static mix3_status_t
process_packet_impl(
            char *packet,
            RSA **keys, int n_keys,
            short *rt_out, char **ri_out, size_t *rs_out,
            char *replay_digest_out)
{
  int i, ok=0;
  char buf[512];
  unsigned char d[SHA1_LEN];
  char *h1 = packet, *h2 = packet + HEADER_LEN, *p = packet + 2 * HEADER_LEN;
  char *junk_start, *ri;
  char *secret, *d_expected;
  int ri_in_pk, data_in_pk;
  uint16_t rs, rt;

  SHA_CTX sha;
  AES_KEY aes_secret;
  AES_KEY aes_junk;

  for (i=0; i < n_keys; ++i) {
    if (mix3_rsa_oaep_dec(buf, sizeof(buf),
                          h1, PK_ENC_LEN, keys[i]) == PK_MAX_DATA_LEN) {
      ok = 1; break;
    }
  }
  if (!ok)
    return MIX3_CORRUPT_PACKET;
  if (buf[0] != 0 || buf[1] != 3)
    return MIX3_BAD_VERSION;
  secret = buf + 2;
  d_expected = buf + 2 + HEADER_SECRET_LEN;
  rs = GET_U16(buf+2+HEADER_SECRET_LEN+SHA1_LEN);
  rt = GET_U16(buf+2+HEADER_SECRET_LEN+SHA1_LEN+2);
  /*XXXX CHECK SIZE.*/
  SHA1((unsigned char *)(h1+PK_ENC_LEN), HEADER_LEN-PK_ENC_LEN, d);
  if (memcmp(d, d_expected, SHA1_LEN))
    return MIX3_CORRUPT_PACKET;

  mix3_aes_subkey_init(&aes_secret,
                       secret, HEADER_SECRET_LEN, "HEADER SECRET KEY");
  *ri_out = mix3_alloc(rs);
  ri = buf+2+HEADER_SECRET_LEN+SHA1_LEN+4;
  ri_in_pk = MIN(rs, PK_MAX_DATA_LEN-(ri-buf));
  data_in_pk = buf+PK_MAX_DATA_LEN-(ri+ri_in_pk);
  memcpy(*ri_out, ri, ri_in_pk);
  mix3_aes_ctr_crypt(*ri_out+ri_in_pk, h1+PK_ENC_LEN, rs-ri_in_pk, &aes_secret);

  memcpy(h1, ri+ri_in_pk, data_in_pk);
  memmove(h1+data_in_pk, h1+PK_ENC_LEN+rs-ri_in_pk,
          HEADER_LEN-PK_ENC_LEN+rs-ri_in_pk);

  mix3_aes_subkey_init(&aes_junk, secret, HEADER_SECRET_LEN, "RANDOM JUNK");
  junk_start = h1+data_in_pk+HEADER_LEN+rs-ri_in_pk;
  mix3_prng(junk_start, h1+HEADER_LEN-junk_start, &aes_junk);
  mix3_aes_ctr_crypt_offset(h1+data_in_pk, h1+data_in_pk,
                        HEADER_LEN-data_in_pk, &aes_secret,
                        rs-ri_in_pk);

  sprp_decrypt(h2, HEADER_LEN, secret, HEADER_SECRET_LEN, "HEADER ENCRYPT");
  sprp_decrypt(p, PAYLOAD_LEN, secret, HEADER_SECRET_LEN, "PAYLOAD ENCRYPT");
  if (RT_IS_SWAP(rt)) {
    char *tmp = mix3_alloc(HEADER_LEN);
    SHA1((unsigned char *)h2, HEADER_LEN, d);
    sprp_decrypt(p, PAYLOAD_LEN, (char*)d, SHA1_LEN, "HIDE PAYLOAD");
    SHA1((unsigned char *)p, PAYLOAD_LEN, d);
    sprp_decrypt(h2, HEADER_LEN, (char*)d, SHA1_LEN, "HIDE HEADER");
    memcpy(tmp, h1, HEADER_LEN);
    memcpy(h1, h2, HEADER_LEN);
    memcpy(h2, tmp, HEADER_LEN);
    memset(tmp, HEADER_LEN, 0);
    mix3_free(tmp);
  }

  *rt_out = rt;
  *rs_out = rs;
  SHA1_Init(&sha);
  SHA1_Update(&sha, d_expected, SHA1_LEN);
  SHA1_Update(&sha, "REPLAY PREVENTION", strlen("REPLAY PREVENTION"));
  SHA1_Final((unsigned char *)replay_digest_out, &sha);

  /* XXXX Set it all to 0. */
}

