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
    memset(&out->recovery.checksum, 0, 32);
    assing_aligned(out->recovery.kid.idx, (uint8_t *)&cp->kidv.id.idx, sizeof(out->recovery.kid.idx));
    assing_aligned(out->recovery.kid.type, (uint8_t *)&cp->kidv.id.type, sizeof(out->recovery.kid.type));
    assing_aligned(out->recovery.kid.sub_idx, (uint8_t *)&cp->kidv.id.sub_idx, sizeof(out->recovery.kid.sub_idx));

    rangeproof_public_xcrypt_kid(&(out->recovery.kid), cp, out->recovery.checksum);

    uint8_t hash_value[32];
    rangeproof_public_get_msg(out, hash_value, oracle);
    signature_sign(hash_value, sk, get_context()->generator.G_pts, &out->signature);
  }
}

void rangeproof_confidential_create(rangeproof_confidential_t *out, const scalar_t *sk,
                                    const rangeproof_creator_params_t *cp, SHA256_CTX *oracle, const secp256k1_gej *h_gen)
{
  // single-pass - use both deterministic and random seed for key blinding.
  // For more safety - use the current oracle state

  SHA256_CTX copy_oracle;
  memcpy(&copy_oracle, oracle, sizeof(SHA256_CTX));
  uint8_t seed_sk[32];
  random_buffer(seed_sk, sizeof(seed_sk));

  sha256_oracle_update_sk(&copy_oracle, sk);
  sha256_Update(&copy_oracle, seed_sk, sizeof(seed_sk));
  sha256_write_64(&copy_oracle, cp->kidv.amount_value);
  sha256_oracle_create(&copy_oracle, seed_sk);

  rangeproof_confidential_co_sign(out, seed_sk, sk, cp, oracle, SINGLE_PASS, NULL, h_gen);
}

int rangeproof_confidential_co_sign(rangeproof_confidential_t *out, const uint8_t *seed_sk, const scalar_t *sk,
                                     const rangeproof_creator_params_t *cp, SHA256_CTX *oracle, phase_t phase, multi_sig_t *msig_out, const secp256k1_gej *h_gen)
{
  nonce_generator_t nonce;
  nonce_generator_init(&nonce, (const uint8_t *)"bulletproof", 12);
  nonce_generator_write(&nonce, cp->seed, 32);

  // A = G*alpha + vec(aL)*vec(G) + vec(aR)*vec(H)
  scalar_t alpha, ro;
  nonce_generator_export_scalar(&nonce, NULL, 0, &alpha);

  // embed extra params into alpha
  static_assert(sizeof(packed_key_idv_t) < 32);
  static_assert(sizeof(rangeproof_creator_params_padded_t) == 32);
  rangeproof_creator_params_padded_t pad;
  memset(pad.padding, 0, sizeof(pad.padding));
  assing_aligned(pad.v.id.idx, (uint8_t *)&cp->kidv.id.idx, sizeof(pad.v.id.idx));
  assing_aligned(pad.v.id.type, (uint8_t *)&cp->kidv.id.type, sizeof(pad.v.id.type));
  assing_aligned(pad.v.id.sub_idx, (uint8_t *)&cp->kidv.id.sub_idx, sizeof(pad.v.id.sub_idx));
  assing_aligned(pad.v.value, (uint8_t *)&cp->kidv.amount_value, sizeof(pad.v.value));

  int overflow;
  scalar_set_b32(&ro, (const uint8_t *)&pad, &overflow);
  if (scalar_import_nnz(&ro, (const uint8_t *)&pad))
  {
    // if overflow - the params won't be recovered properly, there may be ambiguity
  }

  scalar_add(&alpha, &alpha, &ro);

  rangeproof_confidential_calc_a(&out->part1.a, &alpha, cp->kidv.amount_value);

  // S = G*ro + vec(sL)*vec(G) + vec(sR)*vec(H)
  nonce_generator_export_scalar(&nonce, NULL, 0, &ro);

  {
    multi_mac_t mm;
    multi_mac_with_bufs_alloc(&mm, 1, INNER_PRODUCT_N_DIM * 2 + 1);
    mm.k_prepared[mm.n_prepared] = ro;
    mm.prepared[mm.n_prepared++] = (multi_mac_prepared_t *)get_generator_G();

    scalar_t p_s[2][INNER_PRODUCT_N_DIM];

    for (int j = 0; j < 2; j++)
      for (uint32_t i = 0; i < INNER_PRODUCT_N_DIM; i++)
      {
        nonce_generator_export_scalar(&nonce, NULL, 0, &p_s[j][i]);

        mm.k_prepared[mm.n_prepared] = p_s[j][i];
        mm.prepared[mm.n_prepared++] = (multi_mac_prepared_t *)get_generator_ipp(i, j, 0);
      }

    secp256k1_gej comm;
    multi_mac_calculate(&mm, &comm);
    multi_mac_with_bufs_free(&mm);
    export_gej_to_point(&comm, &out->part1.s);
  }

  rangeproof_confidential_challenge_set_t cs;
  rangeproof_confidential_challenge_set_init(&cs, &out->part1, oracle);

  //WIP
  UNUSED(seed_sk);
  UNUSED(phase);
  UNUSED(msig_out);
  UNUSED(h_gen);
  UNUSED(sk);
  return 1;
}

void data_cmov_as(uint32_t *pDst, const uint32_t *pSrc, int nWords, int flag)
{
  const uint32_t mask0 = flag + ~((uint32_t)0);
  const uint32_t mask1 = ~mask0;

  for (int n = 0; n < nWords; n++)
    pDst[n] = (pDst[n] & mask0) | (pSrc[n] & mask1);
}

inline void gej_cmov(secp256k1_gej *dst, const secp256k1_gej *src, int flag)
{
  static_assert(sizeof(secp256k1_gej) % sizeof(uint32_t) == 0);
  data_cmov_as((uint32_t *)dst, (uint32_t *)src, sizeof(secp256k1_gej) / sizeof(uint32_t), flag);
}

void rangeproof_confidential_calc_a(point_t *res, const scalar_t *alpha, uint64_t value)
{
  secp256k1_gej comm;
  generator_mul_scalar(&comm, get_context()->generator.G_pts, alpha);

  {
    secp256k1_gej ge_s;

    for (uint32_t i = 0; i < INNER_PRODUCT_N_DIM; i++)
    {
      uint32_t iBit = 1 & (value >> i);

      // protection against side-channel attacks
      gej_cmov(&ge_s, &get_generator_get1_minus()[i], 0 == iBit);
      gej_cmov(&ge_s, &((multi_mac_prepared_t *)get_generator_ipp(i, 0, 0))->pt[0], 1 == iBit);

      secp256k1_gej_add_var(&comm, &comm, &ge_s, NULL);
    }
  }

  memcpy(res, &comm, sizeof(secp256k1_gej));
}

void rangeproof_confidential_challenge_set_init(rangeproof_confidential_challenge_set_t *cs, const struct Part1 *part1, SHA256_CTX *oracle)
{
  sha256_oracle_update_pt(oracle, &part1->a);
  sha256_oracle_update_pt(oracle, &part1->s);
  
  scalar_create_nnz(oracle, &cs->y);
  scalar_create_nnz(oracle, &cs->z);

  scalar_inverse(&cs->y_inv, &cs->y);
  memcpy(&cs->zz, &cs->z, sizeof(scalar_t));
  scalar_mul(&cs->zz, &cs->zz, &cs->z);
}
