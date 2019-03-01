#include <stdio.h>
#include <string.h>
#include "functions.h"

context_t CONTEXT;

void init_context()
{
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

  generate_G(CONTEXT.generator.G_pts);
}

context_t* get_context()
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
  
  HMAC_SHA256_CTX secret;
  nonce_generator_init(&secret, (const uint8_t *)"beam-HKdf", 10);
  nonce_generator_write(&secret, seed, n);
  nonce_generator_export_output_key(&secret, (const uint8_t *)"gen", 4, 1, okm);
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

void signature_sign(const uint8_t *msg32, const scalar_t *sk, const secp256k1_gej *generator_pts, secp256k1_gej *out_nonce_pub, scalar_t *out_k)
{
  HMAC_SHA256_CTX secret;
  uint8_t bytes[32];
  uint8_t okm[32];

  scalar_get_b32(bytes, sk);

  nonce_generator_init(&secret, (const uint8_t *)"beam-Schnorr", 13);
  nonce_generator_write(&secret, bytes, 32);

  // random_reseed(time(NULL));
  random_buffer(bytes, sizeof(bytes) / sizeof(bytes[0])); // add extra randomness to the nonce, so it's derived from both deterministic and random parts
  nonce_generator_write(&secret, bytes, 32);

  scalar_t multisig_nonce;
  nonce_generator_export_scalar(&secret, NULL, 0, 1, okm, &multisig_nonce);
  generator_mul_scalar(out_nonce_pub, generator_pts, &multisig_nonce);

  signature_sign_partial(&multisig_nonce, out_nonce_pub, msg32, sk, out_k);
}

int signature_is_valid(const uint8_t *msg32, const secp256k1_gej *nonce_pub, const scalar_t *k, const secp256k1_gej *pk, const secp256k1_gej *generator_pts)
{
  scalar_t e;
  signature_get_challenge(nonce_pub, msg32, &e);

  secp256k1_gej pt;
  generator_mul_scalar(&pt, generator_pts, k);

  secp256k1_gej mul_pt;
  gej_mul_scalar(pk, &e, &mul_pt);
  secp256k1_gej_add_var(&pt, &pt, &mul_pt, NULL);
  secp256k1_gej_add_var(&pt, &pt, nonce_pub, NULL);

  return secp256k1_gej_is_infinity(&pt) != 0;
}
