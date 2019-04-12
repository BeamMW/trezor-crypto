#ifndef _RANGEPROOF_H_
#define _RANGEPROOF_H_

#include "definitions.h"
#include "internal.h"
#include "sha2.h"


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
