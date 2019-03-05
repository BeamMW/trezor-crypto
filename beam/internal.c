#include <string.h>
#include "internal.h"

void sha256_write_8(SHA256_CTX *hash, uint8_t b)
{
  sha256_Update(hash, &b, sizeof(b));
}

void sha256_write_64(SHA256_CTX *hash, uint64_t v)
{
  for (; v >= 0x80; v >>= 7)
  {
    sha256_write_8(hash, (uint8_t)((uint8_t)v | 0x80));
  }

  sha256_write_8(hash, (uint8_t)v);
}

int scalar_import_nnz(scalar_t *scalar, const uint8_t *data32)
{
  int overflow;
  scalar_set_b32(scalar, data32, &overflow);
  int zero = scalar_is_zero(scalar);
  return !(overflow || zero);
}

void scalar_create_nnz(SHA256_CTX *orcale, scalar_t *out_scalar)
{
  uint8_t data[32];
  scalar_clear(out_scalar);
  do
  {
    sha256_Final(orcale, data);
    sha256_Update(orcale, data, sizeof(data) / sizeof(data[0]));
  } while (!scalar_import_nnz(out_scalar, data));
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

void point_create_nnz(SHA256_CTX *oracle, secp256k1_gej *out_gej)
{
  point_t pt;
  pt.y = 0;

  do
  {
    sha256_Final(oracle, pt.x);
    sha256_Update(oracle, pt.x, SHA256_DIGEST_LENGTH);
  } while (!point_import_nnz(out_gej, &pt));
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

int create_pts(secp256k1_gej *pPts, secp256k1_gej *gpos, uint32_t nLevels, SHA256_CTX *oracle)
{
  secp256k1_gej nums, npos, pt;

  point_create_nnz(oracle, &nums);

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

void generator_mul_scalar(secp256k1_gej *res, const secp256k1_gej *pPts, const scalar_t* sk)
{
#ifndef BEAM_GENERATE_TABLES
  gej_mul_scalar(pPts, sk, res);
#else
  const uint32_t *p = sk->d;
  const int nWords = sizeof(sk->d) / sizeof(sk->d[0]);

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
#endif
}

void generate_G(secp256k1_gej *generator_pts)
{
  SHA256_CTX oracle;
  sha256_Init(&oracle);
  sha256_Update(&oracle, (const uint8_t *)"Let the generator generation begin!", 36);

  secp256k1_gej G_raw;
  secp256k1_ge G_const = secp256k1_ge_get_const_g();
  secp256k1_gej_set_ge(&G_raw, &G_const);

  while (!create_pts(generator_pts, &G_raw, N_LEVELS, &oracle))
    ;
}

void signature_get_challenge(const secp256k1_gej *pt, const uint8_t *msg32, scalar_t *out_scalar)
{
  point_t p;
  secp256k1_gej point;
  memcpy(&point, pt, sizeof(secp256k1_gej));
  export_gej_to_point(&point, &p);

  SHA256_CTX oracle;
  sha256_Init(&oracle);
  sha256_Update(&oracle, p.x, 32);
  sha256_Update(&oracle, &p.y, 1);
  sha256_Update(&oracle, msg32, 32);

  scalar_create_nnz(&oracle, out_scalar);
}

void signature_sign_partial(const scalar_t *multisig_nonce, const secp256k1_gej *multisig_nonce_pub, const uint8_t *msg, const scalar_t *sk, scalar_t *out_k)
{
  signature_get_challenge(multisig_nonce_pub, msg, out_k);

  scalar_mul(out_k, out_k, sk);
  scalar_add(out_k, out_k, multisig_nonce);
  scalar_negate(out_k, out_k);
}

void fast_aux_schedule(fast_aux_t *aux, const scalar_t *k, unsigned int iBitsRemaining, unsigned int nMaxOdd, unsigned int *pTbl, unsigned int iThisEntry)
{
  const uint32_t *p = k->d;
  const uint32_t nWordBits = sizeof(*p) << 3;

  // assert(1 & nMaxOdd); // must be odd
  unsigned int nVal = 0, nBitTrg = 0;

  while (iBitsRemaining--)
  {
    nVal <<= 1;
    if (nVal > nMaxOdd)
      break;

    uint32_t n = p[iBitsRemaining / nWordBits] >> (iBitsRemaining & (nWordBits - 1));

    if (1 & n)
    {
      nVal |= 1;
      aux->odd = nVal;
      nBitTrg = iBitsRemaining;
    }
  }

  if (nVal > 0)
  {
    aux->next_item = pTbl[nBitTrg];
    pTbl[nBitTrg] = iThisEntry;
  }
}

void gej_mul_scalar(const secp256k1_gej *pt, const scalar_t *sk, secp256k1_gej *res)
{
  static const int nMaxOdd = (1 << 5) - 1;      // 31
  static const int nCount = (nMaxOdd >> 1) + 2; // we need a single even: x2
  static const uint32_t nBytes = 32;
  static const uint32_t nBits = nBytes << 3;

  secp256k1_gej m_pPt[nCount];
  m_pPt[1] = *pt;

  fast_aux_t m_Aux;
  unsigned int m_nPrepared = 1;

  secp256k1_gej_set_infinity(res);

  unsigned int pTblCasual[nBits];
  unsigned int pTblPrepared[nBits];

  memset(pTblCasual, 0, sizeof(pTblCasual));
  memset(pTblPrepared, 0, sizeof(pTblPrepared));

  fast_aux_schedule(&m_Aux, sk, nBits, nMaxOdd, pTblCasual, 1);

  for (unsigned int iBit = nBits; iBit--;)
  {
    if (!secp256k1_gej_is_infinity(res))
      secp256k1_gej_double_var(res, res, NULL);

    while (pTblCasual[iBit])
    {
      unsigned int iEntry = pTblCasual[iBit];
      pTblCasual[iBit] = m_Aux.next_item;

      // assert(1 & m_Aux.odd);
      unsigned int nElem = (m_Aux.odd >> 1) + 1;
      // assert(nElem < nCount);

      for (; m_nPrepared < nElem; m_nPrepared++)
      {
        if (1 == m_nPrepared)
        {
          secp256k1_gej_double_var(&m_pPt[0], &m_pPt[1], NULL);
        }
        secp256k1_gej_add_var(&m_pPt[m_nPrepared + 1], &m_pPt[m_nPrepared], &m_pPt[0], NULL);
      }

      secp256k1_gej_add_var(res, res, &m_pPt[nElem], NULL);

      fast_aux_schedule(&m_Aux, sk, iBit, nMaxOdd, pTblCasual, iEntry);
    }
  }
}
