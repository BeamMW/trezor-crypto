#ifndef _FUNCTIONS_
#define _FUNCTIONS_

#include "internal.h"
#include "definitions.h"

void init_context();

context_t* get_context();

void phrase_to_seed(const char *phrase, uint8_t *out_seed32);

void seed_to_kdf(const uint8_t *seed, size_t n, uint8_t *out_gen32, scalar_t *out_cof);

void generate_hash_id(uint64_t idx, uint32_t type, uint32_t sub_idx, uint8_t *out32);

void derive_key(const uint8_t *parrent, uint8_t parrent_size, const uint8_t *hash_id, uint8_t id_size, const scalar_t *cof_sk, scalar_t *out_sk);

void sk_to_pk(scalar_t *sk, const secp256k1_gej *generator_pts, uint8_t *out32);

void signature_sign(const uint8_t *msg32, const scalar_t *sk, const secp256k1_gej *generator_pts, secp256k1_gej *out_nonce_pub, scalar_t *out_k);

int signature_is_valid(const uint8_t *msg32, const secp256k1_gej *nonce_pub, const scalar_t *k, const secp256k1_gej *pk, const secp256k1_gej *generator_pts);

#endif //_FUNCTIONS_
