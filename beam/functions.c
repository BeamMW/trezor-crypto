#include <stdio.h>
#include <string.h>
#include "functions.h"

//void init_context()
//{
//  CONTEXT.key.Comission = _FOURCC_FROM(fees);
//  CONTEXT.key.Coinbase  = _FOURCC_FROM(mine);
//  CONTEXT.key.Regular   = _FOURCC_FROM(norm);
//  CONTEXT.key.Change    = _FOURCC_FROM(chng);
//  CONTEXT.key.Kernel    = _FOURCC_FROM(kern);   // tests only
//  CONTEXT.key.Kernel2   = _FOURCC_FROM(kerM);  // used by the miner
//  CONTEXT.key.Identity  = _FOURCC_FROM(iden); // Node-Wallet auth
//  CONTEXT.key.ChildKey  = _FOURCC_FROM(SubK);
//  CONTEXT.key.Bbs       = _FOURCC_FROM(BbsM);
//  CONTEXT.key.Decoy     = _FOURCC_FROM(dcoy);
//  CONTEXT.key.Treasury  = _FOURCC_FROM(Tres);
//
//  generate_G(CONTEXT.generator.G_pts);
//}

void phrase_to_seed(const char *phrase, uint8_t *seed32)
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

  DEBUG_PRINT("pbkdf2 of phrase: ", hash, sizeHash);

  SHA256_CTX ctx;
  sha256_Init(&ctx);
  sha256_Update(&ctx, hash, sizeHash);
  sha256_Final(&ctx, seed32);

  DEBUG_PRINT("sha256 of pbkdf2 of phrase: ", seed32, SHA256_DIGEST_LENGTH);
}

void seed_to_kdf(const uint8_t *seed, size_t n, uint8_t *gen32, scalar_t *cof)
{
  HMAC_SHA256_CTX secret;
  uint8_t okm[SHA256_DIGEST_LENGTH];

  nonce_generator_init(&secret, (const uint8_t *)"beam-HKdf", 10);
  nonce_generator_write(&secret, seed, n);

  nonce_generator_export_output_key(&secret, (const uint8_t *)"gen", 4, 1, okm);
  memcpy(gen32, okm, SHA256_DIGEST_LENGTH);

  DEBUG_PRINT("seed_to_kdf (gen): ", okm, SHA256_DIGEST_LENGTH);

  HMAC_SHA256_CTX co_factor;

  nonce_generator_init(&co_factor, (const uint8_t *)"beam-HKdf", 10);
  nonce_generator_write(&co_factor, seed, n);
  nonce_generator_export_scalar(&co_factor, (const uint8_t *)"coF", 4, 1, okm, cof);

  uint8_t scalar_data[32];
  scalar_get_b32(scalar_data, cof);
  DEBUG_PRINT("seed_to_kdf (coF): ", scalar_data, SHA256_DIGEST_LENGTH);
  DEBUG_PRINT("seed_to_kdf from okm (coF): ", okm, SHA256_DIGEST_LENGTH);
}

int scalar_import_nnz(scalar_t *scalar, const uint8_t *data32)
{
  int overflow;
  scalar_set_b32(scalar, data32, &overflow);
  int zero = scalar_is_zero(scalar);
  return !(overflow || zero);
}

void get_first_output_key_material(HMAC_SHA256_CTX *hash, const uint8_t *context, size_t context_size, uint8_t *out32)
{
  uint8_t prk[SHA256_DIGEST_LENGTH];
  const uint8_t number = 1;

  hmac_sha256_Final(hash, prk);
  hmac_sha256_Init(hash, prk, sizeof(prk) / sizeof(prk[0]));

  hmac_sha256_Update(hash, context, context_size);
  hmac_sha256_Update(hash, &number, 1);
  hmac_sha256_Final(hash, out32);
}

void get_rest_output_key_material(HMAC_SHA256_CTX *hash, const uint8_t *context, size_t context_size, uint8_t number, const uint8_t *okm32, uint8_t *out32)
{
  uint8_t prk[SHA256_DIGEST_LENGTH];
  memset(prk, 0, sizeof(prk));
  hmac_sha256_Init(hash, prk, sizeof(prk) / sizeof(prk[0]));

  hmac_sha256_Update(hash, okm32, SHA256_DIGEST_LENGTH);
  hmac_sha256_Update(hash, context, context_size);
  hmac_sha256_Update(hash, &number, 1);
  hmac_sha256_Final(hash, out32);
}

void nonce_generator_init(HMAC_SHA256_CTX *hash, const uint8_t *salt, uint8_t salt_size)
{
  hmac_sha256_Init(hash, (uint8_t *)salt, salt_size);
}

void nonce_generator_write(HMAC_SHA256_CTX *hash, const uint8_t *seed, uint8_t seed_size)
{
  hmac_sha256_Update(hash, seed, seed_size);
}

uint8_t nonce_generator_export_output_key(HMAC_SHA256_CTX *hash, const uint8_t *context, uint8_t context_size, uint8_t number, uint8_t *okm32)
{
  if (1 == number)
  {
    get_first_output_key_material(hash, context, context_size, okm32);
  }
  else
  {
    get_rest_output_key_material(hash, context, context_size, number, okm32, okm32);
  }

  return ++number;
}

uint8_t nonce_generator_export_scalar(HMAC_SHA256_CTX *hash, const uint8_t *context, uint8_t context_size, uint8_t number, uint8_t *okm32, scalar_t *out_scalar)
{
  scalar_clear(out_scalar);
  do
  {
    number = nonce_generator_export_output_key(hash, context, context_size, number, okm32);
  } while (!scalar_import_nnz(out_scalar, okm32));

  return number;
}

static void sha256_write_8(SHA256_CTX *hash, uint8_t b)
{
  sha256_Update(hash, &b, sizeof(b));
}

static void sha256_write_64(SHA256_CTX *hash, uint64_t v)
{
  for (; v >= 0x80; v >>= 7)
  {
    sha256_write_8(hash, (uint8_t)((uint8_t)v | 0x80));
  }

  sha256_write_8(hash, (uint8_t)v);
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

  DEBUG_PRINT("generate_hash_id: ", out32, 32);
}

void derive_key(const uint8_t *parrent, uint8_t parrent_size, const uint8_t *hash_id, uint8_t id_size, scalar_t *cof_sk, scalar_t *res_sk)
{
  HMAC_SHA256_CTX key;
  uint8_t okm[SHA256_DIGEST_LENGTH];

  nonce_generator_init(&key, (const uint8_t *)"beam-Key", 9);
  nonce_generator_write(&key, parrent, parrent_size);
  nonce_generator_write(&key, hash_id, id_size);

  scalar_t a_sk;
  nonce_generator_export_scalar(&key, NULL, 0, 1, okm, &a_sk);
  DEBUG_PRINT("derive_key (a_sk): ", okm, SHA256_DIGEST_LENGTH);

  scalar_clear(res_sk);
  scalar_mul(res_sk, &a_sk, cof_sk);
}

int export_gej_to_point(secp256k1_gej *native_point, point_t *out_point)
{
  if (secp256k1_gej_is_infinity(native_point) != 0)
  {
    memset(out_point, 0, sizeof(point_t));
    return 0;
  }

  secp256k1_ge ge;
  secp256k1_ge_set_gej(&ge, native_point);

  // seems like normalization can be omitted (already done by secp256k1_ge_set_gej), but not guaranteed according to docs.
  // But this has a negligible impact on the performance
  secp256k1_fe_normalize(&ge.x);
  secp256k1_fe_normalize(&ge.y);

  secp256k1_fe_get_b32(out_point->x, &ge.x);
  out_point->y = (secp256k1_fe_is_odd(&ge.y) != 0);

  return 1;
}

void create_point_nnz(secp256k1_gej *gej, SHA256_CTX *oracle)
{
  point_t pt;
  pt.y = 0;

  do
  {
    sha256_Final(oracle, pt.x);
    sha256_Update(oracle, pt.x, SHA256_DIGEST_LENGTH);
  } while (!point_import_nnz(gej, &pt));
}

int point_import_nnz(secp256k1_gej *gej, const point_t *point)
{
  if (point->y > 1)
    return 0; // should always be well-formed

  secp256k1_fe nx;
  if (!secp256k1_fe_set_b32(&nx, point->x))
    return 0;

  secp256k1_ge ge;
  if (!secp256k1_ge_set_xo_var(&ge, &nx, point->y))
    return 0;

  secp256k1_gej_set_ge(gej, &ge);

  return 1;
}

int create_pts(secp256k1_gej *pPts, secp256k1_gej *gpos, uint32_t nLevels, SHA256_CTX *oracle)
{
  secp256k1_gej nums, npos, pt;

  create_point_nnz(&nums, oracle);

  secp256k1_gej_add_var(&nums, &nums, gpos, NULL);
  npos = nums;

  for (uint32_t iLev = 1;; iLev++)
  {
    pt = npos;

    for (uint32_t iPt = 1;; iPt++)
    {
      if (secp256k1_gej_is_infinity(&pt) != 0)
        return 0;

      *pPts++ = pt;

      if (iPt == N_POINTS_PER_LEVEL)
        break;

      secp256k1_gej_add_var(&pt, &pt, gpos, NULL);
    }

    if (iLev == nLevels)
      break;

    for (uint32_t i = 0; i < N_BITS_PER_LEVEL; i++)
    {
      secp256k1_gej_double_var(gpos, gpos, NULL);
    }

    secp256k1_gej_double_var(&npos, &npos, NULL);
    if (iLev + 1 == nLevels)
    {
      secp256k1_gej_neg(&npos, &npos);
      secp256k1_gej_add_var(&npos, &npos, &nums, NULL);
    }
  }

  return 1;
}

void set_mul(secp256k1_gej *res, const secp256k1_gej *pPts, const uint32_t *p, int nWords)
{
  int bSet = 1;
  static_assert(8 % N_BITS_PER_LEVEL == 0);
  const int nLevelsPerWord = (sizeof(uint32_t) << 3) / N_BITS_PER_LEVEL;
  static_assert(!(nLevelsPerWord & (nLevelsPerWord - 1))); // should be power-of-2

  // iterating in lsb to msb order
  for (int iWord = 0; iWord < nWords; iWord++)
  {
    uint32_t n = p[iWord];
    for (int j = 0; j < nLevelsPerWord; j++, pPts += N_POINTS_PER_LEVEL)
    {
      uint32_t nSel = (N_POINTS_PER_LEVEL - 1) & n;
      n >>= N_BITS_PER_LEVEL;

      /** This uses a conditional move to avoid any secret data in array indexes.
					*   _Any_ use of secret indexes has been demonstrated to result in timing
					*   sidechannels, even when the cache-line access patterns are uniform.
					*  See also:
					*   "A word of warning", CHES 2013 Rump Session, by Daniel J. Bernstein and Peter Schwabe
					*    (https://cryptojedi.org/peter/data/chesrump-20130822.pdf) and
					*   "Cache Attacks and Countermeasures: the Case of AES", RSA 2006,
					*    by Dag Arne Osvik, Adi Shamir, and Eran Tromer
					*    (http://www.tau.ac.il/~tromer/papers/cache.pdf)
					*/

      const secp256k1_gej *pSel;
      pSel = pPts + nSel;

      if (bSet)
      {
        *res = *pSel;
      }
      else
      {
        secp256k1_gej_add_var(res, res, pSel, NULL);
      }
      bSet = 0;
    }
  }
}

void generate_G(secp256k1_gej *generator_pts)
{
  SHA256_CTX oracle;
  sha256_Init(&oracle);
  sha256_Update(&oracle, (const uint8_t *)"Let the generator generation begin!", 36);

  secp256k1_gej G_raw;
  secp256k1_gej_set_ge(&G_raw, &secp256k1_ge_const_g);

  while (!create_pts(generator_pts, &G_raw, N_LEVELS, &oracle))
    ;
}

void sk_to_pk(scalar_t *sk, const secp256k1_gej *generator_pts, uint8_t *out32)
{
  secp256k1_gej ptn;
  set_mul(&ptn, generator_pts, sk->d, 8);

  point_t p;
  export_gej_to_point(&ptn, &p);
  if (p.y)
  {
    scalar_negate(sk, sk);
  }

  memcpy(out32, p.x, 32);
}
