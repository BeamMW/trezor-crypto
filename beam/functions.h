#ifndef _FUNCTIONS_
#define _FUNCTIONS_

#include "../pbkdf2.h"
#include "../sha2.h"
#include "../hmac.h"
#include "../rand.h"
#include "lib/scalar32.h"
#include "lib/group.h"

#define DEBUG_PRINT(msg, arr, len) \
  printf(msg);                     \
  for (size_t i = 0; i < len; i++) \
  {                                \
    printf("%02x", arr[i]);        \
  }                                \
  printf("\n");

#define N_BYTES             32
#define N_BITS              (N_BYTES << 3)
#define N_BITS_PER_LEVEL    4
#define N_POINTS_PER_LEVEL  (1 << N_BITS_PER_LEVEL) //16
#define N_LEVELS            (N_BITS / N_BITS_PER_LEVEL)

#define static_assert(condition)((void)sizeof(char[1 - 2 * !(condition)]))

typedef struct
{
  uint8_t x[32];
  uint8_t y;
} point_t;

typedef struct
{
  uint32_t Comission;
  uint32_t Coinbase;
  uint32_t Regular;
  uint32_t Change;
  uint32_t Kernel;
  uint32_t Kernel2;
  uint32_t Identity;
  uint32_t ChildKey;
  uint32_t Bbs;
  uint32_t Decoy;
  uint32_t Treasury;
} key_types_t;

typedef struct
{
  secp256k1_gej G_pts[N_LEVELS * N_POINTS_PER_LEVEL];
} generators_t;

typedef struct
{
  key_types_t key;
  generators_t generator;
} context_t;

typedef struct
{
  unsigned int next_item;
  unsigned int odd;
} fast_aux_t;

context_t CONTEXT;

#define _COUNT_OF(_Array) (sizeof(_Array) / sizeof(_Array[0]))
#define _FOURCC_CONST(a, b, c, d) ((uint32_t)((((((uint8_t)a << 8) | (uint8_t)b) << 8) | (uint8_t)c) << 8) | (uint8_t)d)
#define _ARRAY_ELEMENT_SAFE(arr, index) ((arr)[(((index) < _COUNT_OF(arr)) ? (index) : (_COUNT_OF(arr) - 1))])
#define _FOURCC_FROM(name) _FOURCC_CONST(_ARRAY_ELEMENT_SAFE(#name, 0), _ARRAY_ELEMENT_SAFE(#name, 1), _ARRAY_ELEMENT_SAFE(#name, 2), _ARRAY_ELEMENT_SAFE(#name, 3))

void init_context();

void phrase_to_seed(const char *phrase, uint8_t *seed32);

void seed_to_kdf(const uint8_t *seed, size_t n, uint8_t *gen32, scalar_t *cof);

int scalar_import_nnz(scalar_t *scalar, const uint8_t *data32);

void get_first_output_key_material(HMAC_SHA256_CTX *hash, const uint8_t *context, size_t context_size, uint8_t *out32);

void get_rest_output_key_material(HMAC_SHA256_CTX *hash, const uint8_t *context, size_t context_size, uint8_t number, const uint8_t *okm32, uint8_t *out32);

void nonce_generator_init(HMAC_SHA256_CTX *hash, const uint8_t *salt, uint8_t salt_size);

void nonce_generator_write(HMAC_SHA256_CTX *hash, const uint8_t *seed, uint8_t seed_size);

uint8_t nonce_generator_export_output_key(HMAC_SHA256_CTX *hash, const uint8_t *context, uint8_t context_size, uint8_t number, uint8_t *okm32);

uint8_t nonce_generator_export_scalar(HMAC_SHA256_CTX *hash, const uint8_t *context, uint8_t context_size, uint8_t number, uint8_t *okm32, scalar_t *out_scalar);

void generate_hash_id(uint64_t idx, uint32_t type, uint32_t sub_idx, uint8_t *out32);

void derive_key(const uint8_t *parrent, uint8_t parrent_size, const uint8_t *hash_id, uint8_t id_size, scalar_t *cof_sk, scalar_t *res_sk);

int export_gej_to_point(secp256k1_gej *native_point, point_t *out_point);

int point_import_nnz(secp256k1_gej *gej, const point_t *point);

void create_point_nnz(secp256k1_gej *gej, SHA256_CTX *oracle);

int create_pts(secp256k1_gej *pPts, secp256k1_gej *gpos, uint32_t nLevels, SHA256_CTX *oracle);

void set_mul(secp256k1_gej *res, const secp256k1_gej *pPts, const uint32_t *p, int nWords);

void generate_G(secp256k1_gej *generator_pts);

void sk_to_pk(scalar_t *sk, const secp256k1_gej *generator_pts, uint8_t *out32);

void signature_sign(const uint8_t *msg32, const scalar_t *sk, const secp256k1_gej *generator_pts, secp256k1_gej *out_nonce_pub, scalar_t *out_k);

int signature_is_valid(const uint8_t *msg32, const secp256k1_gej *nonce_pub, const scalar_t *k, const secp256k1_gej *pk, const secp256k1_gej *generator_pts);

#endif //_FUNCTIONS_
