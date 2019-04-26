#include "rangeproof.h"
#include "functions.h"
#include "misc.h"
#include "memzero.h"


int tag_is_custom(const secp256k1_gej *h_gen)
{
  // secp256k1_gej_is_infinity == 0 means thath h_gen is zero
  return (h_gen != NULL) && (secp256k1_gej_is_infinity(h_gen) == 0);
}

void tag_add_value(const secp256k1_gej *h_gen, uint64_t value, secp256k1_gej *out)
{
  scalar_t value_scalar;
  scalar_set_u64(&value_scalar, value);
  secp256k1_gej mul_result;

  if (tag_is_custom(h_gen))
    gej_mul_scalar(h_gen, &value_scalar, &mul_result);
  else
    generator_mul_scalar(&mul_result, get_context()->generator.H_pts, &value_scalar);

  secp256k1_gej_add_var(out, out, &mul_result, NULL);
}

void asset_tag_commit(const secp256k1_gej *h_gen, const scalar_t *sk, uint64_t value, secp256k1_gej *out)
{
  generator_mul_scalar(out, get_context()->generator.G_pts, sk);
  tag_add_value(h_gen, value, out);
}

void rangeproof_public_xcrypt_kid(packed_key_id_t *kid, const rangeproof_creator_params_t *cp, uint8_t *checksum)
{
  nonce_generator_t nonce;
  nonce_generator_init(&nonce, (const uint8_t *)"beam-psig", 10);
  nonce_generator_write(&nonce, cp->seed, 32);
  nonce_generator_export_output_key(&nonce, NULL, 0, NULL);
  memxor((uint8_t *)kid, nonce.okm, sizeof(packed_key_id_t));
  nonce_generator_export_output_key(&nonce, NULL, 0, NULL);
  memcpy(checksum, nonce.okm, 32);
}

void rangeproof_public_get_msg(rangeproof_public_t *rp, uint8_t *hash32, SHA256_CTX *oracle)
{
  sha256_write_64(oracle, rp->value);
  sha256_Update(oracle, (const uint8_t *)&rp->recovery, sizeof(rp->recovery));
  sha256_oracle_create(oracle, hash32);
}

void rangeproof_public_create(rangeproof_public_t *out, const scalar_t *sk, const rangeproof_creator_params_t *cp, SHA256_CTX *oracle)
{
  out->value = cp->kidv.value;
  if (out->value >= _RANGEPROOF_AMOUNT_MINIMUM_VALUE)
  {
    memset(&out->recovery.kid, 0, sizeof(out->recovery.kid));
    assing_aligned(out->recovery.kid.idx, (uint8_t *)&cp->kidv.id.idx, sizeof(out->recovery.kid.idx));
    assing_aligned(out->recovery.kid.type, (uint8_t *)&cp->kidv.id.type, sizeof(out->recovery.kid.type));
    assing_aligned(out->recovery.kid.sub_idx, (uint8_t *)&cp->kidv.id.sub_idx, sizeof(out->recovery.kid.sub_idx));

    rangeproof_public_xcrypt_kid(&(out->recovery.kid), cp, out->recovery.checksum);

    uint8_t hash_value[32];
    rangeproof_public_get_msg(out, hash_value, oracle);
    signature_sign(hash_value, sk, get_context()->generator.G_pts, &out->signature);
  }
}

void rangeproof_creator_params_init(rangeproof_creator_params_t* crp)
{
    memzero(crp->seed, DIGEST_LENGTH);
    key_idv_init(&crp->kidv);
}

void rangeproof_public_init(rangeproof_public_t* public)
{
    signature_init(&public->signature);
    public->value = 0;
    rangeproof_public_recovery_init(&public->recovery);
}

void rangeproof_public_recovery_init(rangeproof_public_recovery_t* recovery)
{
    memzero(recovery->checksum, DIGEST_LENGTH);
    packed_key_id_init(&recovery->kid);
}
