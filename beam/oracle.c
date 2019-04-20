#include "oracle.h"
#include "internal.h"

void sha256_oracle_update_gej(SHA256_CTX *oracle, const secp256k1_gej *gej)
{
  point_t pt;
  export_gej_to_point(gej, &pt);
  sha256_oracle_update_pt(oracle, &pt);
}

void sha256_oracle_update_pt(SHA256_CTX *oracle, const point_t *pt)
{
  sha256_Update(oracle, pt->x, 32);
  sha256_write_8(oracle, pt->y);
}

void sha256_oracle_update_sk(SHA256_CTX *oracle, const scalar_t *sk)
{
  uint8_t sk_bytes[32];
  memset(sk_bytes, 0, 32);
  scalar_get_b32(sk_bytes, sk);
  sha256_Update(oracle, sk_bytes, 32);
}