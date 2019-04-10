#ifndef __BEAM_KERNEL__
#define __BEAM_KERNEL__

#ifndef BEAM_DEBUG
#include "mpconfigport.h"
#endif


void ecc_tag_add_value(const secp256k1_gej* h_gen, uint64_t value, secp256k1_gej* out);
void switch_commitment_create(scalar_t* sk, secp256k1_gej* commitment, HKdf_t* kdf,
                              const key_id_value_t* kidv, int has_commitment, const secp256k1_gej* h_gen);
void switch_commitment_get_sk1(const secp256k1_gej* commitment, const secp256k1_gej* sk0_j,
                               scalar_t* scalar_out);
void peer_finalize_excess(scalar_t* peer_scalar, secp256k1_gej* kG, scalar_t* k_offset);
void peer_add_input(tx_inputs_vec_t* tx_inputs,
                    scalar_t* peer_scalar, transaction_t* t,
                    uint64_t val, HKdf_t* kdf,
                    const uint8_t* asset_id)
void create_tx_kernel(tx_kernel_t* trg_kernels, uint32_t num_trg_kernels,
                      tx_kernel_t* nested_kernels, uint32_t num_nested_kernels,
                      uint64_t fee, uint32_t should_emit_custom_tag);
int kernel_traverse(const tx_kernel_t* kernel, const tx_kernel_t* parent_kernel,
                    const uint8_t* hash_lock_preimage,
                    uint8_t* hash_value, uint8_t* fee,
                    secp256k1_gej* excess);
void kernel_get_hash(const tx_kernel_t* kernel, const uint8_t* hash_lock_preimage, uint8_t* out);
void cosign_kernel_part_1(tx_kernel_t* kernel,
                          secp256k1_gej* kG, secp256k1_gej* xG,
                          scalar_t* peer_scalars, scalar_t* peer_nonces, size_t num_peers,
                          scalar_t* transaction_offset, uint8_t kernel_hash_message,
                          const uint8_t* hash_lock_preimage);

#endif // __BEAM_KERNEL__
