#ifndef _INNER_PRODUCT_H_
#define _INNER_PRODUCT_H_

#include "definitions.h"
#include "internal.h"
#include "multi_mac.h"
#include "oracle.h"
#include "sha2.h"

#define INNER_PRODUCT_N_DIM     64U // sizeof(uint64_t/*amount*/) << 3
#define INNER_PRODUCT_N_CYCLES  6U
#define INNER_PRODUCT_I_CYCLE_0 2 // condense source generators into points (after 3 iterations, 8 points)

typedef struct
{
  const scalar_t *multiplier[2];
} inner_product_modifier_t;

typedef struct
{
  scalar_t pwr[2][INNER_PRODUCT_N_DIM];
  uint8_t use[2];
} _calculator_modifier_expanded_t;

typedef struct
{
  scalar_t val[INNER_PRODUCT_N_CYCLES];
} _challenge_set_xset_t;

typedef struct
{
  scalar_t dot_multiplier;
  _challenge_set_xset_t x[2];
} _calculator_challenge_set_t;

typedef struct
{
  _calculator_modifier_expanded_t mod;
  _calculator_challenge_set_t cs;
  multi_mac_t mm;
  const scalar_t *src[2];
  secp256k1_gej gen[2][INNER_PRODUCT_N_DIM >> (1 + INNER_PRODUCT_I_CYCLE_0)];
  scalar_t val[2][INNER_PRODUCT_N_DIM >> 1];

  uint32_t i_cycle;
  uint32_t n;
  uint32_t gen_order;
} inner_product_calculator_t;

typedef struct
{
  multi_mac_t *mm;
  const _challenge_set_xset_t *x[2];
  const _calculator_modifier_expanded_t *mod;
  const inner_product_calculator_t *calc;
  int j;
  unsigned int i_cycle_trg;
} _calculator_aggregator_t;

typedef struct
{
  point_t LR[INNER_PRODUCT_N_CYCLES][2];
  scalar_t condensed[2];
} inner_product_t;

void inner_product_modifier_init(inner_product_modifier_t *mod);

void inner_product_get_dot(scalar_t *out, const scalar_t *a, const scalar_t *b);

void calculator_aggregator_init(_calculator_aggregator_t *ag, multi_mac_t *mm,
                                const _challenge_set_xset_t *x, const _challenge_set_xset_t *x_inv, const _calculator_modifier_expanded_t *mod,
                                int j, unsigned int i_cycle_trg);

void calculator_modifier_expanded_init(_calculator_modifier_expanded_t *mod_ex, const inner_product_modifier_t *mod);

void calculator_modifier_expanded_set(const _calculator_modifier_expanded_t *mod_ex, scalar_t *dst, const scalar_t *src, int i, int j);

void calculator_aggregator_proceed(_calculator_aggregator_t *ag, uint32_t i_pos, uint32_t i_cycle, const scalar_t *k);

void calculator_aggregator_proceed_rec(_calculator_aggregator_t *ag, uint32_t i_pos, uint32_t i_cycle, const scalar_t *k, uint32_t j);

void inner_product_calculator_extract_LR(inner_product_calculator_t *calc, int j);

void inner_product_calculator_condense(inner_product_calculator_t *calc);

void inner_product_create(inner_product_t *in, SHA256_CTX *oracle, secp256k1_gej *ab, const scalar_t *dot_ab,
                          const scalar_t *a, const scalar_t *b, inner_product_modifier_t *mod);

#endif //_INNER_PRODUCT_H_