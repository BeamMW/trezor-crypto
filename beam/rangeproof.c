#include "rangeproof.h"
#include "functions.h"

secp256k1_gej switch_commitment(const uint8_t *asset_id)
{
  secp256k1_gej h_gen;
  if (asset_id && !(memis0(asset_id, 32)))
  {
    SHA256_CTX oracle;
    sha256_Init(&oracle);
    sha256_Update(&oracle, (const uint8_t *)"a-id", 5);
    sha256_Update(&oracle, asset_id, 32);

    point_t pt;
    pt.y = 0;

    do
    {
      sha256_Update(&oracle, (const uint8_t *)"a-gen", 6);

      SHA256_CTX new_oracle;
      memcpy(&new_oracle, &oracle, sizeof(SHA256_CTX));
      sha256_Final(&new_oracle, pt.x);

      sha256_Update(&oracle, pt.x, SHA256_DIGEST_LENGTH);
    } while (!point_import_nnz(&h_gen, &pt));
  }
  else
  {
    secp256k1_gej_set_infinity(&h_gen);
  }
  return h_gen;
}

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
  out->value = cp->kidv.amount_value;
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
