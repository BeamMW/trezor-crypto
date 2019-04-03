#ifndef _FUNCTIONS_
#define _FUNCTIONS_

#include "internal.h"
#include "definitions.h"

void init_context(void);

void free_context(void);

context_t* get_context(void);

void phrase_to_seed(const char *phrase, uint8_t *out_seed32);

void seed_to_kdf(const uint8_t *seed, size_t n, uint8_t *out_gen32, scalar_t *out_cof);

void generate_hash_id(uint64_t idx, uint32_t type, uint32_t sub_idx, uint8_t *out32);

void derive_key(const uint8_t *parrent, uint8_t parrent_size, const uint8_t *hash_id, uint8_t id_size, const scalar_t *cof_sk, scalar_t *out_sk);

void sk_to_pk(scalar_t *sk, const secp256k1_gej *generator_pts, uint8_t *out32);

void signature_sign(const uint8_t *msg32, const scalar_t *sk, const secp256k1_gej *generator_pts, ecc_signature_t* signature);

int signature_is_valid(const uint8_t *msg32, const ecc_signature_t* signature, const secp256k1_gej *pk, const secp256k1_gej *generator_pts);

void get_child_kdf(const uint8_t *parent_secret_32, const scalar_t *parent_cof, uint32_t index, uint8_t *out32_child_secret, scalar_t *out_child_cof);

uint8_t *get_owner_key(const uint8_t *master_key, const scalar_t *master_cof, const uint8_t *secret, size_t secret_size);

#endif //_FUNCTIONS_