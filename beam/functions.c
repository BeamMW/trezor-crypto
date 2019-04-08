#include "functions.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

context_t CONTEXT;

void init_context(void)
{
  static uint8_t is_first_init = 1;
  if (is_first_init)
  {
    CONTEXT.generator.G_pts = NULL;
    CONTEXT.generator.J_pts = NULL;
    CONTEXT.generator.H_pts = NULL;
    is_first_init = 0;
  }
  
  CONTEXT.key.Comission = _FOURCC_FROM(fees);
  CONTEXT.key.Coinbase  = _FOURCC_FROM(mine);
  CONTEXT.key.Regular   = _FOURCC_FROM(norm);
  CONTEXT.key.Change    = _FOURCC_FROM(chng);
  CONTEXT.key.Kernel    = _FOURCC_FROM(kern); // tests only
  CONTEXT.key.Kernel2   = _FOURCC_FROM(kerM); // used by the miner
  CONTEXT.key.Identity  = _FOURCC_FROM(iden); // Node-Wallet auth
  CONTEXT.key.ChildKey  = _FOURCC_FROM(SubK);
  CONTEXT.key.Bbs       = _FOURCC_FROM(BbsM);
  CONTEXT.key.Decoy     = _FOURCC_FROM(dcoy);
  CONTEXT.key.Treasury  = _FOURCC_FROM(Tres);

  free_context();
#ifndef BEAM_USE_TABLES
  CONTEXT.generator.G_pts = get_generator_G();
  CONTEXT.generator.J_pts = get_generator_J();
  CONTEXT.generator.H_pts = get_generator_H();
#else
#ifndef BEAM_GENERATE_TABLES 
  CONTEXT.generator.G_pts = get_generator_lut_G();
  CONTEXT.generator.J_pts = get_generator_lut_J();
  CONTEXT.generator.H_pts = get_generator_lut_H();
#else
  CONTEXT.generator.G_pts = malloc((N_LEVELS * N_POINTS_PER_LEVEL) * sizeof(secp256k1_gej));
  CONTEXT.generator.J_pts = malloc((N_LEVELS * N_POINTS_PER_LEVEL) * sizeof(secp256k1_gej));
  CONTEXT.generator.H_pts = malloc((N_LEVELS * N_POINTS_PER_LEVEL) * sizeof(secp256k1_gej));
  generate_points(CONTEXT.generator.G_pts, CONTEXT.generator.J_pts, CONTEXT.generator.H_pts);
#endif
#endif
}

void free_context(void) {
#if !defined(BEAM_USE_TABLES) || !defined(BEAM_GENERATE_TABLES)
  CONTEXT.generator.G_pts = NULL;
  CONTEXT.generator.J_pts = NULL;
  CONTEXT.generator.H_pts = NULL;
#else
  if (CONTEXT.generator.G_pts)
  {
    free(CONTEXT.generator.G_pts);
    CONTEXT.generator.G_pts = NULL;
  }
  if (CONTEXT.generator.J_pts)
  {
    free(CONTEXT.generator.J_pts);
    CONTEXT.generator.J_pts = NULL;
  }
  if (CONTEXT.generator.H_pts)
  {
    free(CONTEXT.generator.H_pts);
    CONTEXT.generator.H_pts = NULL;
  }
#endif
}

context_t* get_context(void)
{
  return &CONTEXT;
}

void phrase_to_seed(const char *phrase, uint8_t *out_seed32)
{
  const char salt[] = "mnemonic";
  const size_t sizeHash = 512 >> 3;
  const size_t hmacIterations = 2048;
  uint8_t hash[sizeHash];

  pbkdf2_hmac_sha512(
      (const uint8_t *)phrase,
      strlen(phrase),
      (const uint8_t *)salt,
      strlen(salt),
      hmacIterations,
      hash,
      sizeHash);

  SHA256_CTX ctx;
  sha256_Init(&ctx);
  sha256_Update(&ctx, hash, sizeHash);
  sha256_Final(&ctx, out_seed32);
}

void seed_to_kdf(const uint8_t *seed, size_t n, uint8_t *out_gen32, scalar_t *out_cof)
{
  uint8_t okm[SHA256_DIGEST_LENGTH];
  uint8_t prk[SHA256_DIGEST_LENGTH];
  memset(prk, 0, sizeof(prk));

  HMAC_SHA256_CTX secret;
  nonce_generator_init(&secret, (const uint8_t *)"beam-HKdf", 10);
  nonce_generator_write(&secret, seed, n);
  nonce_generator_export_output_key(prk, &secret, (const uint8_t *)"gen", 4, 1, okm);
  memcpy(out_gen32, okm, SHA256_DIGEST_LENGTH);

  HMAC_SHA256_CTX co_factor;
  nonce_generator_init(&co_factor, (const uint8_t *)"beam-HKdf", 10);
  nonce_generator_write(&co_factor, seed, n);
  nonce_generator_export_scalar(&co_factor, (const uint8_t *)"coF", 4, 1, okm, out_cof);
}

void generate_hash_id(uint64_t idx, uint32_t type, uint32_t sub_idx, uint8_t *out32)
{
  SHA256_CTX x;
  sha256_Init(&x);
  sha256_Update(&x, (const uint8_t *)"kid", 4);
  sha256_write_64(&x, idx);
  sha256_write_64(&x, type);
  sha256_write_64(&x, sub_idx);
  sha256_Final(&x, out32);
}

void derive_key(const uint8_t *parrent, uint8_t parrent_size, const uint8_t *hash_id, uint8_t id_size, const scalar_t *cof_sk, scalar_t *out_sk)
{
  HMAC_SHA256_CTX key;
  uint8_t okm[SHA256_DIGEST_LENGTH];

  nonce_generator_init(&key, (const uint8_t *)"beam-Key", 9);
  nonce_generator_write(&key, parrent, parrent_size);
  nonce_generator_write(&key, hash_id, id_size);

  scalar_t a_sk;
  nonce_generator_export_scalar(&key, NULL, 0, 1, okm, &a_sk);

  scalar_clear(out_sk);
  scalar_mul(out_sk, &a_sk, cof_sk);
}

void sk_to_pk(scalar_t *sk, const secp256k1_gej *generator_pts, uint8_t *out32)
{
  secp256k1_gej ptn;
  generator_mul_scalar(&ptn, generator_pts, sk);

  point_t p;
  export_gej_to_point(&ptn, &p);
  if (p.y)
  {
    scalar_negate(sk, sk);
  }

  memcpy(out32, p.x, 32);
}

void signature_sign(const uint8_t *msg32, const scalar_t *sk, const secp256k1_gej *generator_pts, ecc_signature_t* signature)
{
  HMAC_SHA256_CTX secret;
  uint8_t bytes[32];
  uint8_t okm[32];

  scalar_get_b32(bytes, sk);

  nonce_generator_init(&secret, (const uint8_t *)"beam-Schnorr", 13);
  nonce_generator_write(&secret, bytes, 32);

  random_buffer(bytes, sizeof(bytes) / sizeof(bytes[0])); // add extra randomness to the nonce, so it's derived from both deterministic and random parts
  nonce_generator_write(&secret, bytes, 32);

  scalar_t multisig_nonce;
  nonce_generator_export_scalar(&secret, NULL, 0, 1, okm, &multisig_nonce);
  generator_mul_scalar(&signature->nonce_pub, generator_pts, &multisig_nonce);

  signature_sign_partial(&multisig_nonce, &signature->nonce_pub, msg32, sk, &signature->k);
}

int signature_is_valid(const uint8_t *msg32, const ecc_signature_t* signature, const secp256k1_gej *pk, const secp256k1_gej *generator_pts)
{
  scalar_t e;
  signature_get_challenge(&signature->nonce_pub, msg32, &e);

  secp256k1_gej pt;
  generator_mul_scalar(&pt, generator_pts, &signature->k);

  secp256k1_gej mul_pt;
  gej_mul_scalar(pk, &e, &mul_pt);
  secp256k1_gej_add_var(&pt, &pt, &mul_pt, NULL);
  secp256k1_gej_add_var(&pt, &pt, &signature->nonce_pub, NULL);

  return secp256k1_gej_is_infinity(&pt) != 0;
}

void get_child_kdf(const uint8_t *parent_secret_32, const scalar_t *parent_cof, uint32_t index, uint8_t *out32_child_secret, scalar_t *out_child_cof)
{
  if (!index)
  { // by convention 0 is not a child
    memcpy(out32_child_secret, parent_secret_32, 32);
    memcpy(out_child_cof, parent_cof, sizeof(scalar_t));
    return;
  }
  uint8_t child_id[32];
  scalar_t child_key;
  uint8_t child_scalar_data[32];
  generate_hash_id(index, CONTEXT.key.ChildKey, 0, child_id);
  derive_key(parent_secret_32, 32, child_id, 32, parent_cof, &child_key);
  scalar_get_b32(child_scalar_data, &child_key);

  seed_to_kdf(child_scalar_data, 32, out32_child_secret, out_child_cof);
}

uint8_t* get_owner_key(const uint8_t *master_key, const scalar_t *master_cof, const uint8_t *secret, size_t secret_size)
{
  uint8_t child_secret_key[32];
  scalar_t child_cofactor;
  get_child_kdf(master_key, master_cof, 0, child_secret_key, &child_cofactor);

  HKdf_packed_t packed;
  generate_HKdfPub(child_secret_key, &child_cofactor, CONTEXT.generator.G_pts, CONTEXT.generator.J_pts, &packed);

  uint8_t p[sizeof(HKdf_packed_t)];
  memcpy(p, &packed, sizeof(HKdf_packed_t));
  return export_encrypted(p, sizeof(HKdf_packed_t), 'P', secret, secret_size, (const uint8_t*)"0", 1);
}
