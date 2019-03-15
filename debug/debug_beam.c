#include <string.h>
#include <malloc.h>
#include <time.h>
#include "../beam/functions.h"

#define DIGEST_LENGTH 32

#define VERIFY_TEST(x)                                                \
  do                                                                  \
  {                                                                   \
    if (!(x))                                                         \
      printf("Test failed! Line=%u, Expression: %s\n", __LINE__, #x); \
    else                                                              \
      printf("Test passed! Line=%u, Expression: %s\n", __LINE__, #x); \
  } while (0)

#define DEBUG_PRINT(msg, arr, len)           \
  printf("Line=%u, Msg=%s ", __LINE__, msg); \
  for (size_t i = 0; i < len; i++)           \
  {                                          \
    printf("%02x", arr[i]);                  \
  }                                          \
  printf("\n");

int main(void)
{
  srand(time(NULL));
  init_context();

  uint8_t seed[DIGEST_LENGTH];
  phrase_to_seed("edge video genuine moon vibrant hybrid forum climb history iron involve sausage", seed);
  // phrase_to_seed("tomato provide age upon voice fetch nest night parent pilot evil furnace", seed);
  DEBUG_PRINT("sha256 of pbkdf2 of phrase: ", seed, DIGEST_LENGTH);

  uint8_t secret_key[DIGEST_LENGTH];
  scalar_t cofactor;
  uint8_t cofactor_data[DIGEST_LENGTH];
  seed_to_kdf(seed, DIGEST_LENGTH, secret_key, &cofactor);
  scalar_get_b32(cofactor_data, &cofactor);
  DEBUG_PRINT("seed_to_kdf (gen / secret_key): ", secret_key, DIGEST_LENGTH);
  DEBUG_PRINT("seed_to_kdf (coF): ", cofactor_data, DIGEST_LENGTH);

  uint8_t id[DIGEST_LENGTH];
  generate_hash_id(123456, get_context()->key.Bbs, 0, id);
  DEBUG_PRINT("generate_hash_id: ", id, DIGEST_LENGTH);

  scalar_t key;
  uint8_t key_data[DIGEST_LENGTH];
  derive_key(secret_key, DIGEST_LENGTH, id, DIGEST_LENGTH, &cofactor, &key);
  scalar_get_b32(key_data, &key);
  DEBUG_PRINT("derive_key (res): ", key_data, DIGEST_LENGTH);

  uint8_t new_address_data[DIGEST_LENGTH];
  sk_to_pk(&key, get_context()->generator.G_pts, new_address_data);
  DEBUG_PRINT("sk_to_pk: ", new_address_data, DIGEST_LENGTH);

  uint8_t msg[64];
  random_buffer(msg, 64);
  DEBUG_PRINT("generated message: ", msg, 64);

  secp256k1_gej nonce;
  point_t nonce_point;
  scalar_t k;
  uint8_t k_data[DIGEST_LENGTH];
  signature_sign(msg, &key, get_context()->generator.G_pts, &nonce, &k);
  scalar_get_b32(k_data, &k);
  export_gej_to_point(&nonce, &nonce_point);
  DEBUG_PRINT("signature_sign k: ", k_data, DIGEST_LENGTH);
  DEBUG_PRINT("signature_sign nonce_point.x: ", nonce_point.x, DIGEST_LENGTH);

  secp256k1_gej pk;
  generator_mul_scalar(&pk, get_context()->generator.G_pts, &key);
  VERIFY_TEST(signature_is_valid(msg, &nonce, &k, &pk, get_context()->generator.G_pts)); // passed
  msg[0]++;
  VERIFY_TEST(signature_is_valid(msg, &nonce, &k, &pk, get_context()->generator.G_pts)); // failed

  char* owner_key = get_owner_key(secret_key, &cofactor, (uint8_t*)"qwerty", 7);
  printf("owner_key = %s\n\n", owner_key);
  free(owner_key);

  free_context();
  malloc_stats();
}