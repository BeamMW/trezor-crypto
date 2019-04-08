#ifndef _TYPES_
#define _TYPES_

// #ifndef BEAM_DEBUG
// #include "mpconfigport.h"
// #endif

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

typedef struct
{
  secp256k1_gej nonce_pub;
  scalar_t k;
} ecc_signature_t;

typedef struct
{
  uint64_t idx;
  uint32_t type;
  uint32_t sub_idx;
} key_id_t;

#define _RANGEPROOF_AMOUNT_MINIMUM_VALUE 1
typedef struct
{
  key_id_t id;
  uint64_t amount_value;
} key_idv_t;

#pragma pack(push, 1)
  typedef struct // use arrays for fields ???
  {
    uint8_t idx[8];
    uint8_t type[4];
    uint8_t sub_idx[4];
  } packed_key_id_t;
#pragma pack(pop)

typedef struct
{
  uint8_t seed[32];
  key_idv_t kidv;
} rangeproof_creator_params_t;

#pragma pack(push, 1)
  typedef struct
  {
    packed_key_id_t kid;
    uint8_t checksum[32];
  } rangeproof_public_recovery_t;
#pragma pack(pop)

typedef struct
{
  ecc_signature_t signature;
  uint64_t value;

  rangeproof_public_recovery_t recovery;
} rangeproof_public_t;

typedef struct
{
  // Bulletproof scheme

  struct Part1 {
    point_t a;
    point_t s;
  } part1;

  // <- y,z

  struct Part2 {
    point_t t1;
    point_t t2;
  } part2;

  // <- x

  struct Part3 {
    scalar_t tauX;
  } part3;

  scalar_t mu;
  scalar_t tDot;

#define _RANGEPROOF_CONFIDENTIAL_NCYCLES 6
  struct InnerProduct {
    point_t pair_LR[_RANGEPROOF_CONFIDENTIAL_NCYCLES][2];  // pairs of L,R values, per reduction iteration
    scalar_t condensed[2];        // remaining 1-dimension vectors
  } p_tag; // contains commitment P - m_Mu*G
} rangeproof_confidential_t;

typedef struct
{
  point_t commitment;
  uint64_t maturity_height; // used in macroblocks only
} tx_element_t;

typedef struct
{
  ecc_signature_t signature;    // For the whole body, including nested kernels
  uint64_t fee;                 // can be 0 (for instance for coinbase transactions)
  uint64_t min_height;
  uint64_t max_height;
  int64_t asset_emission;       // in case it's non-zero - the kernel commitment is the AssetID

  uint8_t hash_lock_preimage[32];
  tx_element_t tx_element;
} _tx_kernel_t;

typedef struct
{
  _tx_kernel_t kernel;

  uint32_t num_nested_kernels;
  _tx_kernel_t* nested_kernels;
} tx_kernel_t;

typedef struct
{
  tx_element_t tx_element;
  uint64_t _id; // used internally. Not serialized/transferred
} tx_input_t;

typedef struct
{
  tx_element_t tx_element;
  uint32_t is_coinbase; // 0 - regular output. 1 - coinbase
  uint64_t incubation_height; // # of blocks before it's mature
  uint8_t asset_id[32]; // type of ECC:Hash::Value

  // one of the following *must* be specified

  rangeproof_confidential_t* confidential_proof;
  rangeproof_public_t* public_proof;
} tx_output_t;

typedef struct
{
  scalar_t offset;
  tx_input_t* inputs;
  tx_output_t* outputs;
  tx_kernel_t* kernels;
} transaction_t;

secp256k1_gej *get_generator_lut_G(void);

secp256k1_gej *get_generator_lut_J(void);

secp256k1_gej *get_generator_lut_H(void);

secp256k1_gej *get_generator_G(void);

secp256k1_gej *get_generator_J(void);

secp256k1_gej *get_generator_H(void);

#endif //_TYPES_
