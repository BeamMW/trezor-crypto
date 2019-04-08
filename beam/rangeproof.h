#ifndef _RANGEPROOF_H_
#define _RANGEPROOF_H_

#include "definitions.h"
#include "internal.h"
#include "sha2.h"

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

void rangeproof_public_xcrypt_kid(packed_key_id_t *kid, const rangeproof_creator_params_t *cp, uint8_t *checksum)
{
  HMAC_SHA256_CTX nonce;
  nonce_generator_init(&nonce, (const uint8_t *)"beam-psig", 10);
  nonce_generator_write(&nonce, cp->seed, 32);

  uint8_t okm[32];
  uint8_t number = 1;
  uint8_t prk[SHA256_DIGEST_LENGTH];
  memset(prk, 0, sizeof(prk));
  number = nonce_generator_export_output_key(prk, &nonce, NULL, 0, number, okm);
  memxor((uint8_t *)kid, okm, sizeof(packed_key_id_t));
  nonce_generator_export_output_key(prk, &nonce, NULL, 0, number, okm);
  memcpy(checksum, okm, 32);
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

    // TODO: Implement the rest
    UNUSED(sk);
    UNUSED(oracle);
    // Hash::Value hv;
    // get_Msg(hv, oracle);

    // m_Signature.Sign(hv, sk);
  }
}


int tag_is_custom(const secp256k1_gej* h_gen)
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
#endif //_RANGEPROOF_H_