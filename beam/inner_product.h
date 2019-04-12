#include "definitions.h"
#include "internal.h"
#include "sha2.h"

#define INNER_PRODUCT_N_DIM    64U // sizeof(uint64_t/*amount*/) << 3
#define INNER_PRODUCT_N_CYCLES 6U

typedef struct
{
  const scalar_t *multiplier[2];
} inner_product_modifier_t;

typedef struct
{
  scalar_t pwr[2][INNER_PRODUCT_N_DIM];
  uint8_t use[2];
} _inner_product_modifier_expanded_t;

typedef struct
{
  _inner_product_modifier_expanded_t mod;
  uint32_t gen_order;
  const scalar_t *src[2];
} inner_product_calculator_t;

void inner_product_modifier_init(inner_product_modifier_t *mod)
{
  memset(mod->multiplier, 0, sizeof(mod->multiplier));
}

void inner_product_get_dot(scalar_t *out, const scalar_t *a, const scalar_t *b)
{
  *out = a[0];
  scalar_mul(out, out, &b[0]);

  scalar_t tmp;
  for (size_t i = 1; i < INNER_PRODUCT_N_DIM; i++)
  {
    tmp = a[i];
    scalar_mul(&tmp, &tmp, &b[i]);
    scalar_add(out, out, &tmp);
  }
}

void inner_product_modifier_expanded_init(_inner_product_modifier_expanded_t *mod_ex, const inner_product_modifier_t *mod)
{
  const size_t count = sizeof(mod->multiplier) / sizeof(mod->multiplier[0]);
  for (size_t j = 0; j < count; j++)
  {
    mod_ex->use[j] = (NULL != mod->multiplier[j]);
    if (mod_ex->use[j])
    {
      scalar_set_int(&mod_ex->pwr[j][0], 1U);
      for (size_t i = 1; i < INNER_PRODUCT_N_DIM; i++)
        scalar_mul(&mod_ex->pwr[j][i], &mod_ex->pwr[j][i - 1], mod->multiplier[j]);
    }
  }
}

void inner_product_modifier_expanded_set(_inner_product_modifier_expanded_t *mod_ex, scalar_t *dst, const scalar_t *src, int i, int j)
{
  if (mod_ex->use[j])
    scalar_mul(dst, src, &mod_ex->pwr[j][i]);
  else
    *dst = *src;
}

void inner_product_create(SHA256_CTX *oracle, const secp256k1_gej *ab, const scalar_t *dot_ab,
                          const scalar_t *a, const scalar_t *b, inner_product_modifier_t *mod)
{
  inner_product_calculator_t calc;
  inner_product_modifier_expanded_init(&calc.mod, mod);
  calc.gen_order = INNER_PRODUCT_N_CYCLES;
  calc.src[0] = a;
  calc.src[1] = b;

  if (ab)
  {
    for (uint32_t j = 0; j < 2; j++)
      // for (uint32_t i = 0; i < INNER_PRODUCT_N_DIM; i++, c.m_Mm.m_Prepared++)
      {
        // c.m_Mm.m_ppPrepared[c.m_Mm.m_Prepared] = &Context::get().m_Ipp.m_pGen_[j][i];
        // inner_product_modifier_expanded_set(&calc.mod, ...)
      }

    // c.m_Mm.Calculate(*pAB);
    // oracle << *pAB;
  }
  // ...
}