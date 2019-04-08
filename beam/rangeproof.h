#include "definitions.h"
#include "internal.h"
#include "sha2.h"

int memis0(const void *p, size_t n)
{
  for (size_t i = 0; i < n; i++)
    if (((const uint8_t *)p)[i])
      return 0;
  return 1;
}

void memxor(uint8_t *pDst, const uint8_t *pSrc, size_t n)
{
  for (size_t i = 0; i < n; i++)
    pDst[i] ^= pSrc[i];
}

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
#define DEBUG_PRINT(msg, arr, len)           \
  printf("Line=%u, Msg=%s ", __LINE__, msg); \
  for (size_t i = 0; i < len; i++)           \
  {                                          \
    printf("%02x", arr[i]);                  \
  }                                          \
  printf("\n");
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
  DEBUG_PRINT("okm", okm, 32);
  DEBUG_PRINT("kid", ((uint8_t *)kid), sizeof(packed_key_id_t));
  memxor((uint8_t *)kid, okm, sizeof(packed_key_id_t));
  DEBUG_PRINT("okm-xor", ((uint8_t *)kid), sizeof(packed_key_id_t));

  nonce_generator_export_output_key(prk, &nonce, NULL, 0, number, okm);
  memcpy(checksum, okm, 32);
}

void assing_aligned(uint8_t *dest, uint8_t *src, size_t bytes)
{
  for (size_t i = bytes; i--; src++)
    dest[i] = *src;
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
    // Hash::Value hv;
    // get_Msg(hv, oracle);

    // m_Signature.Sign(hv, sk);
  }
}
