#include <string.h>
#include <malloc.h>
#include <time.h>
#include "../beam/functions.h"
#include "base64.h"
#include "../beam/rangeproof.h"
#include "../beam/kernel.h"

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#define VERIFY_TEST(x)                                                                                                        \
  do                                                                                                                          \
  {                                                                                                                           \
    if (!(x))                                                                                                                 \
      printf(ANSI_COLOR_RED "Test failed!" ANSI_COLOR_CYAN " Line=%u" ANSI_COLOR_RESET ", Expression: %s\n", __LINE__, #x);   \
    else                                                                                                                      \
      printf(ANSI_COLOR_GREEN "Test passed!" ANSI_COLOR_CYAN " Line=%u" ANSI_COLOR_RESET ", Expression: %s\n", __LINE__, #x); \
  } while (0)

#define DEBUG_PRINT(msg, arr, len)                                               \
  printf(ANSI_COLOR_CYAN "Line=%u" ANSI_COLOR_RESET ", Msg=%s ", __LINE__, msg); \
  printf(ANSI_COLOR_YELLOW);                                                     \
  for (size_t i = 0; i < len; i++)                                               \
  {                                                                              \
    printf("%02x", arr[i]);                                                      \
  }                                                                              \
  printf(ANSI_COLOR_RESET "\n");

void printAsBytes(const char *name, const void *mem, size_t len)
{
  uint8_t tmp[len];
  memcpy(tmp, mem, len);
  printf("const uint8_t %s[] = { ", name);
  for (size_t i = 0; i < len; i++)
  {
    if (i < len - 1)
      printf("0x%02x, ", tmp[i]);
    else
      printf("0x%02x };", tmp[i]);
  }
  printf("\n\n");
}

inline void hex2bin(const char *hex_string, const size_t size_string, uint8_t *out_bytes)
{
  uint32_t buffer = 0;
  for (size_t i = 0; i < size_string / 2; i++)
  {
    sscanf(hex_string + 2 * i, "%2X", &buffer);
    out_bytes[i] = buffer;
  }
}

int IS_EQUAL_HEX(const char *hex_str, const uint8_t *bytes, size_t str_size)
{
  uint8_t tmp[str_size / 2];
  hex2bin(hex_str, str_size, tmp);
  return memcmp(tmp, bytes, str_size / 2) == 0;
}

int main(void)
{
  random_reseed(time(NULL));
  init_context();

  uint8_t seed[DIGEST_LENGTH];
  phrase_to_seed("edge video genuine moon vibrant hybrid forum climb history iron involve sausage", seed);
  //phrase_to_seed("tomato provide age upon voice fetch nest night parent pilot evil furnace", seed);
  DEBUG_PRINT("sha256 of pbkdf2 of phrase: ", seed, DIGEST_LENGTH);
  VERIFY_TEST(IS_EQUAL_HEX("751b77ab415ed14573b150b66d779d429e48cd2a40c51bf6ce651ce6c38fd620", seed, 64));

  uint8_t secret_key[DIGEST_LENGTH];
  scalar_t cofactor;
  uint8_t cofactor_data[DIGEST_LENGTH];
  seed_to_kdf(seed, DIGEST_LENGTH, secret_key, &cofactor);
  scalar_get_b32(cofactor_data, &cofactor);
  DEBUG_PRINT("seed_to_kdf (gen / secret_key): ", secret_key, DIGEST_LENGTH);
  VERIFY_TEST(IS_EQUAL_HEX("d497d3d7dc9819a80e9035dd99d0877ebd61fd4cc7c19ee9a796c0aea6d04faf", secret_key, 64));
  DEBUG_PRINT("seed_to_kdf (coF): ", cofactor_data, DIGEST_LENGTH);
  VERIFY_TEST(IS_EQUAL_HEX("d6265c09c4ace3d6d01cb5528149fb0d751a2d5fa69172b67ee5cc9c1a320e73", cofactor_data, 64));

  uint8_t id[DIGEST_LENGTH];
  generate_hash_id(123456, get_context()->key.Bbs, 0, id);
  DEBUG_PRINT("generate_hash_id: ", id, DIGEST_LENGTH);
  VERIFY_TEST(IS_EQUAL_HEX("8d3a2b7de4c7757cdd8591a06db8c2d85dfec748ec598baaa5dc1ede8d171fd2", id, 64));

  scalar_t key;
  uint8_t key_data[DIGEST_LENGTH];
  derive_key(secret_key, DIGEST_LENGTH, id, DIGEST_LENGTH, &cofactor, &key);
  scalar_get_b32(key_data, &key);
  DEBUG_PRINT("derive_key (res): ", key_data, DIGEST_LENGTH);
  VERIFY_TEST(IS_EQUAL_HEX("1569368acd9ae88d2dd008643753312034c39c20d77ea27a5ac5091e9541d782", key_data, 64));

  uint8_t new_address_data[DIGEST_LENGTH];
  sk_to_pk(&key, get_context()->generator.G_pts, new_address_data);
  DEBUG_PRINT("sk_to_pk: ", new_address_data, DIGEST_LENGTH);
  VERIFY_TEST(IS_EQUAL_HEX("e27ba10a67f9b95140e2c6771df5b29674118832d3a51d2b79640370575538e4", new_address_data, 64));

  uint8_t msg[64];
  random_buffer(msg, 64);
  DEBUG_PRINT("generated message: ", msg, 64);

  point_t nonce_point;
  uint8_t k_data[DIGEST_LENGTH];
  ecc_signature_t signature;
  signature_sign(msg, &key, get_context()->generator.G_pts, &signature);
  scalar_get_b32(k_data, &signature.k);
  export_gej_to_point(&signature.nonce_pub, &nonce_point);
  DEBUG_PRINT("signature_sign k: ", k_data, DIGEST_LENGTH);
  DEBUG_PRINT("signature_sign nonce_point.x: ", nonce_point.x, DIGEST_LENGTH);

  secp256k1_gej pk;
  generator_mul_scalar(&pk, get_context()->generator.G_pts, &key);
  VERIFY_TEST(signature_is_valid(msg, &signature, &pk, get_context()->generator.G_pts)); // passed
  msg[0]++;
  VERIFY_TEST(!signature_is_valid(msg, &signature, &pk, get_context()->generator.G_pts)); // failed

  uint8_t* owner_key = get_owner_key(secret_key, &cofactor, (uint8_t*)"qwerty", 7);
  DEBUG_PRINT("owner_key: ", owner_key, 108);
  char* owner_key_encoded = b64_encode(owner_key, 108);
  printf("owner_key encoded:" ANSI_COLOR_YELLOW " %s\n" ANSI_COLOR_RESET, owner_key_encoded);
  VERIFY_TEST(0 == strcmp("mJrVrOiyjaMFCjxRsfGahBkiVzC+ymIXDv2qJdJxR4WMBY4rCJ+vTkkcCdVXw41pays2TuZAFJZbDyvqD89dYxzjudp3oZeTIZQQI1LnPOG92oZB4WRNvts8lJ943DSMvi3o/YotxhnTQPc2", owner_key_encoded));
  free(owner_key);
  free(owner_key_encoded);

  // Range proof
  const uint8_t asset_id[] = {0xcc, 0xb2, 0xcd, 0xc6, 0x9b, 0xb4, 0x54, 0x11, 0x0e, 0x82, 0x74, 0x41, 0x21, 0x3d, 0xdc, 0x87, 0x70, 0xe9, 0x3e, 0xa1, 0x41, 0xe1, 0xfc, 0x67, 0x3e, 0x01, 0x7e, 0x97, 0xea, 0xdc, 0x6b, 0x96};
  const uint8_t sk_bytes[] = {0x96, 0x6b, 0xdc, 0xea, 0x97, 0x7e, 0x01, 0x3e, 0x67, 0xfc, 0xe1, 0x41, 0xa1, 0x3e, 0xe9, 0x70, 0x87, 0xdc, 0x3d, 0x21, 0x41, 0x74, 0x82, 0x0e, 0x11, 0x54, 0xb4, 0x9b, 0xc6, 0xcd, 0xb2, 0xab};

  secp256k1_gej asset_tag_h_gen;
  switch_commitment(asset_id, &asset_tag_h_gen);
  printf("\n\nAssetTag: expected: 1caeb2f, real: ");
  printf("%x", asset_tag_h_gen.x.n[0]);
  printf("\n");
  
  rangeproof_creator_params_t crp;
  memset(crp.seed, 1, 32);
  crp.kidv.value = 345000;
  crp.kidv.id.idx = 1;
  crp.kidv.id.type = 11;
  crp.kidv.id.sub_idx = 111;

  scalar_t sk;
  scalar_set_b32(&sk, sk_bytes, NULL);
  rangeproof_public_t rp;
  SHA256_CTX oracle;

  memset(rp.recovery.checksum, 0, 32);
  rangeproof_public_create(&rp, &sk, &crp, &oracle);
  DEBUG_PRINT("checksum:", rp.recovery.checksum, 32);
  VERIFY_TEST(IS_EQUAL_HEX("fb4c45f75b6bc159d0d17afd1700896c33eb3fb8b95d6c6a917dd34f2766e47d", rp.recovery.checksum, 64));
  secp256k1_gej comm;
  asset_tag_commit(&asset_tag_h_gen, &sk, crp.kidv.value, &comm);
  printAsBytes("comm", &comm, sizeof(comm));
  free_context();
  malloc_stats();
}
