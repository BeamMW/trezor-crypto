#ifndef _RANGEPROOF_H_
#define _RANGEPROOF_H_

#include "definitions.h"
#include "internal.h"
#include "oracle.h"

#define _RANGEPROOF_AMOUNT_MINIMUM_VALUE 1

typedef struct
{
  uint8_t seed[32];
  key_idv_t kidv;
} rangeproof_creator_params_t;

#pragma pack(push, 1)
typedef struct
{
  packed_key_id_t kid;
  uint8_t checksum[32];
} rangeproof_public_recovery_t;
#pragma pack(pop)

typedef struct
{
  ecc_signature_t signature;
  uint64_t value;

  rangeproof_public_recovery_t recovery;
} rangeproof_public_t;

secp256k1_gej switch_commitment(const uint8_t *asset_id);

int tag_is_custom(const secp256k1_gej* h_gen);

void tag_add_value(const secp256k1_gej *h_gen, uint64_t value, secp256k1_gej *out);

void asset_tag_commit(const secp256k1_gej *h_gen, const scalar_t *sk, uint64_t value, secp256k1_gej *out);

void rangeproof_public_xcrypt_kid(packed_key_id_t *kid, const rangeproof_creator_params_t *cp, uint8_t *checksum);

void rangeproof_public_get_msg(rangeproof_public_t *rp, uint8_t *hash32, SHA256_CTX *oracle);

void rangeproof_public_create(rangeproof_public_t *out, const scalar_t *sk, const rangeproof_creator_params_t *cp, SHA256_CTX *oracle);

#endif //_RANGEPROOF_H_
