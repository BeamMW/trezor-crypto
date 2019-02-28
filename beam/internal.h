#ifndef _INTERNAL_FUNCTIONS_
#define _INTERNAL_FUNCTIONS_

#include "crypto/pbkdf2.h"
#include "crypto/sha2.h"
#include "crypto/hmac.h"
#include "crypto/rand.h"
#include "definitions.h"

void sha256_write_8(SHA256_CTX *hash, uint8_t b);

void sha256_write_64(SHA256_CTX *hash, uint64_t v);

int scalar_import_nnz(scalar_t *scalar, const uint8_t *data32);

void scalar_create_nnz(SHA256_CTX *orcale, scalar_t *out_scalar);

int point_import_nnz(secp256k1_gej *gej, const point_t *point);

void point_create_nnz(SHA256_CTX *oracle, secp256k1_gej *out_gej);

int export_gej_to_point(secp256k1_gej *native_point, point_t *out_point);

void get_first_output_key_material(HMAC_SHA256_CTX *hash, const uint8_t *context, size_t context_size, uint8_t *out32);

void get_rest_output_key_material(HMAC_SHA256_CTX *hash, const uint8_t *context, size_t context_size, uint8_t number, const uint8_t *okm32, uint8_t *out32);

void nonce_generator_init(HMAC_SHA256_CTX *hash, const uint8_t *salt, uint8_t salt_size);

void nonce_generator_write(HMAC_SHA256_CTX *hash, const uint8_t *seed, uint8_t seed_size);

uint8_t nonce_generator_export_output_key(HMAC_SHA256_CTX *hash, const uint8_t *context, uint8_t context_size, uint8_t number, uint8_t *okm32);

uint8_t nonce_generator_export_scalar(HMAC_SHA256_CTX *hash, const uint8_t *context, uint8_t context_size, uint8_t number, uint8_t *okm32, scalar_t *out_scalar);

int create_pts(secp256k1_gej *pPts, secp256k1_gej *gpos, uint32_t nLevels, SHA256_CTX *oracle);

void generator_mul_scalar(secp256k1_gej *res, const secp256k1_gej *pPts, const scalar_t *sk);

void generate_G(secp256k1_gej *generator_pts);

void signature_get_challenge(const secp256k1_gej *pt, const uint8_t *msg32, scalar_t *out_scalar);

void signature_sign_partial(const scalar_t *multisig_nonce, const secp256k1_gej *multisig_nonce_pub, const uint8_t *msg, const scalar_t *sk, scalar_t *out_k);

void fast_aux_schedule(fast_aux_t *aux, const scalar_t *k, unsigned int iBitsRemaining, unsigned int nMaxOdd, unsigned int *pTbl, unsigned int iThisEntry);

void gej_mul_scalar(const secp256k1_gej *pt, scalar_t *sk, secp256k1_gej *res);

#endif //_INTERNAL_FUNCTIONS_