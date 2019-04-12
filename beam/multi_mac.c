#include "multi_mac.h"

void multi_mac_casual_init(multi_mac_casual_t *casual, const secp256k1_gej *p, const scalar_t *k)
{
  casual->pt[1] = *p;
  casual->prepared = 1;
  casual->k = *k;
}

void multi_mac_fast_aux_schedule(_multi_mac_fast_aux_t *aux, const scalar_t *k, unsigned int iBitsRemaining, unsigned int nMaxOdd, unsigned int *pTbl, unsigned int iThisEntry)
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

void multi_mac_calculate(multi_mac_t *mm, secp256k1_gej *res)
{
  static const uint32_t nBytes = 32;
  static const uint32_t nBits = nBytes << 3;

  secp256k1_gej_set_infinity(res);

  uint32_t pTblCasual[nBits];
  // unsigned int pTblPrepared[nBits];

  memset(pTblCasual, 0, sizeof(pTblCasual));
  // memset(pTblPrepared, 0, sizeof(pTblPrepared));

  for (size_t i = 0; i < mm->n_casual; i++)
  {
    multi_mac_casual_t *x = &mm->casual[i];
    multi_mac_fast_aux_schedule(&x->aux, &x->k, nBits, MULTI_MAC_CASUAL_MAX_ODD, pTblCasual, i + 1);
  }

  for (unsigned int iBit = nBits; iBit--;)
  {
    if (!secp256k1_gej_is_infinity(res))
      secp256k1_gej_double_var(res, res, NULL);

    while (pTblCasual[iBit])
    {
      unsigned int iEntry = pTblCasual[iBit];
      multi_mac_casual_t *x = &mm->casual[iEntry - 1];
      pTblCasual[iBit] = x->aux.next_item;

      // assert(1 & m_Aux.odd);
      unsigned int nElem = (x->aux.odd >> 1) + 1;
      // assert(nElem < nCount);

      for (; x->prepared < nElem; x->prepared++)
      {
        if (1 == x->prepared)
          secp256k1_gej_double_var(&x->pt[0], &x->pt[1], NULL);
        secp256k1_gej_add_var(&x->pt[x->prepared + 1], &x->pt[x->prepared], &x->pt[0], NULL);
      }
      secp256k1_gej_add_var(res, res, &x->pt[nElem], NULL);

      multi_mac_fast_aux_schedule(&x->aux, &x->k, iBit, MULTI_MAC_CASUAL_MAX_ODD, pTblCasual, iEntry);
    }
  }
}
