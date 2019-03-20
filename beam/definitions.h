#ifndef _TYPES_
#define _TYPES_

#ifndef BEAM_DEBUG
#include "mpconfigport.h"
#endif

#include "lib/group.h"
#include "lib/scalar32.h"

#define N_BYTES 32
#define N_BITS (N_BYTES << 3)
#define N_BITS_PER_LEVEL 4
#define N_POINTS_PER_LEVEL (1 << N_BITS_PER_LEVEL) //16
#define N_LEVELS (N_BITS / N_BITS_PER_LEVEL)

#define _COUNT_OF(_Array) (sizeof(_Array) / sizeof(_Array[0]))
#define _FOURCC_CONST(a, b, c, d) ((uint32_t)((((((uint8_t)a << 8) | (uint8_t)b) << 8) | (uint8_t)c) << 8) | (uint8_t)d)
#define _ARRAY_ELEMENT_SAFE(arr, index) ((arr)[(((index) < _COUNT_OF(arr)) ? (index) : (_COUNT_OF(arr) - 1))])
#define _FOURCC_FROM(name) _FOURCC_CONST(_ARRAY_ELEMENT_SAFE(#name, 0), _ARRAY_ELEMENT_SAFE(#name, 1), _ARRAY_ELEMENT_SAFE(#name, 2), _ARRAY_ELEMENT_SAFE(#name, 3))

#define static_assert(condition)((void)sizeof(char[1 - 2 * !(condition)]))

typedef struct
{
  uint8_t x[32];
  uint8_t y;
} point_t;

typedef struct
{
  uint32_t Comission;
  uint32_t Coinbase;
  uint32_t Regular;
  uint32_t Change;
  uint32_t Kernel;
  uint32_t Kernel2;
  uint32_t Identity;
  uint32_t ChildKey;
  uint32_t Bbs;
  uint32_t Decoy;
  uint32_t Treasury;
} key_types_t;

typedef struct
{
  secp256k1_gej *G_pts;
  secp256k1_gej *J_pts;
  secp256k1_gej *H_pts;
} generators_t;

typedef struct
{
  key_types_t key;
  generators_t generator;
} context_t;

typedef struct
{
  unsigned int next_item;
  unsigned int odd;
} fast_aux_t;

#pragma pack(push, 1)
typedef struct
{
  uint8_t secret[32];
  point_t pkG;
  point_t pkJ;
} HKdf_packed_t;
#pragma pack(pop)

secp256k1_gej *get_generator_G(void);

secp256k1_gej *get_generator_J(void);

secp256k1_gej *get_generator_H(void);

#endif //_TYPES_
