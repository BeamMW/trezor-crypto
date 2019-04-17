#include <string.h>

#include "internal.h"
#include "functions.h"
#include "../rand.h"
#include "misc.h"

//void free_tx_kernels_vec(tx_kernels_vec_t* kernels)
//{
//    int i = 0;
//    tx_kernel_t** kernel = NULL;
//    vec_foreach_ptr(kernels, kernel, i) {
//        // Get inner pointer and free it
//        free(*kernel);
//    }
//    vec_deinit(kernels);
//}
void ecc_tag_add_value(const secp256k1_gej* h_gen, uint64_t value, secp256k1_gej* out)
{
    // gej_is_infinity == 0 means thath h_gen is zero
    int is_custom_h_gen = (h_gen != NULL) && (secp256k1_gej_is_infinity(h_gen) == 0);
    scalar_t value_scalar;
    scalar_set_u64(&value_scalar, value);
    secp256k1_gej mul_result;

    if (is_custom_h_gen)
        gej_mul_scalar(h_gen, &value_scalar, &mul_result);
    else
        generator_mul_scalar(&mul_result, get_context()->generator.H_pts, &value_scalar);

    secp256k1_gej_add_var(out, out, &mul_result, NULL);
}

// sk0_J is a result of multiplication of derived key and generator J
void switch_commitment_get_sk1(const secp256k1_gej* commitment, const secp256k1_gej* sk0_j, scalar_t* scalar_out)
{
    SHA256_CTX x;
    sha256_Init(&x);

    point_t commitment_point;
    export_gej_to_point((secp256k1_gej*)commitment, &commitment_point);

    point_t sk0_j_point;
    export_gej_to_point((secp256k1_gej*)sk0_j, &sk0_j_point);

    sha256_Update(&x, commitment_point.x, DIGEST_LENGTH);
    sha256_write_8(&x, commitment_point.y);
    sha256_Update(&x, sk0_j_point.x, DIGEST_LENGTH);
    sha256_write_8(&x, sk0_j_point.y);

    uint8_t scalar_res[32];
    sha256_Final(&x, scalar_res);
    scalar_import_nnz(scalar_out, scalar_res);
}

void switch_commitment(const uint8_t *asset_id, secp256k1_gej* h_gen)
{
  if (asset_id && !(memis0(asset_id, 32)))
  {
    SHA256_CTX oracle;
    sha256_Init(&oracle);
    sha256_Update(&oracle, (const uint8_t *)"a-id", 5);
    sha256_Update(&oracle, asset_id, 32);

    point_t pt;
    pt.y = 0;

    do
    {
      sha256_Update(&oracle, (const uint8_t *)"a-gen", 6);

      SHA256_CTX new_oracle;
      memcpy(&new_oracle, &oracle, sizeof(SHA256_CTX));
      sha256_Final(&new_oracle, pt.x);

      sha256_Update(&oracle, pt.x, SHA256_DIGEST_LENGTH);
    } while (!point_import_nnz(h_gen, &pt));
  }
  else
  {
    secp256k1_gej_set_infinity(h_gen);
  }
}

void switch_commitment_create(scalar_t* sk, secp256k1_gej* commitment, HKdf_t* kdf, const key_idv_t* kidv, int has_commitment, const secp256k1_gej* h_gen)
{
    uint8_t hash_id[DIGEST_LENGTH];
    generate_hash_id(kidv->id.idx, kidv->id.type, kidv->id.sub_idx, hash_id);

    derive_key(kdf->generator_secret, DIGEST_LENGTH, hash_id, DIGEST_LENGTH, &kdf->cofactor, sk);

    // Multiply key by generator G
    generator_mul_scalar(commitment, get_context()->generator.G_pts, sk);
    ecc_tag_add_value(h_gen, kidv->value, commitment);

    // Multiply key by generator J
    secp256k1_gej key_j_mul_result;
    generator_mul_scalar(&key_j_mul_result, get_context()->generator.J_pts, sk);

    scalar_t sk1;
    switch_commitment_get_sk1(commitment, &key_j_mul_result, &sk1);
    scalar_add(sk, sk, &sk1);

    if (has_commitment)
    {
        secp256k1_gej sk1_g_mul_result;
        generator_mul_scalar(&sk1_g_mul_result, get_context()->generator.G_pts, &sk1);
        secp256k1_gej_add_var(commitment, commitment, &sk1_g_mul_result, NULL);
    }
}

void peer_finalize_excess(scalar_t* peer_scalar, secp256k1_gej* kG, scalar_t* k_offset)
{
    scalar_add(k_offset, k_offset, peer_scalar);

    uint8_t random_scalar_data[DIGEST_LENGTH];
    //random_buffer(random_scalar_data, DIGEST_LENGTH);
    test_set_buffer(random_scalar_data, DIGEST_LENGTH, 3);
    scalar_set_b32(peer_scalar, random_scalar_data, NULL);
    scalar_add(k_offset, k_offset, peer_scalar);

    scalar_negate(peer_scalar, peer_scalar);

    secp256k1_gej peer_scalar_mul_g;
    generator_mul_scalar(&peer_scalar_mul_g, get_context()->generator.G_pts, peer_scalar);
    secp256k1_gej_add_var(kG, kG, &peer_scalar_mul_g, NULL);
}

void peer_add_input(tx_inputs_vec_t* tx_inputs, scalar_t* peer_scalar, uint64_t val, HKdf_t* kdf, const uint8_t* asset_id)
{
    tx_input_t* input = malloc(sizeof(tx_input_t));

    key_idv_t kidv;
    //TEST<Kirill A>: Test only
    //kidv.idx = 1;
    //random_buffer((uint8_t*)&kidv.id.idx, sizeof(kidv.id.idx));
    test_set_buffer((uint8_t*)&kidv.id.idx, sizeof(kidv.id.idx), 3);
    kidv.id.sub_idx = 0;
    kidv.id.type = get_context()->key.Regular;
    kidv.value = val;

    scalar_t k;
    secp256k1_gej h_gen;
    switch_commitment(asset_id, &h_gen);
    secp256k1_gej commitment_native;
    point_import_nnz(&commitment_native, &input->tx_element.commitment);
    switch_commitment_create(&k, &commitment_native, kdf, &kidv, 1, &h_gen);
    // Write result back to TxInput
    export_gej_to_point(&commitment_native, &input->tx_element.commitment);

    // Push TxInput to vec of inputs
    vec_push(tx_inputs, input);

    scalar_add(peer_scalar, peer_scalar, &k);
}

// AmountBig::Type is 128 bits = 16 bytes
int kernel_traverse(const tx_kernel_t* kernel, const tx_kernel_t* parent_kernel,
                    const uint8_t* hash_lock_preimage,
                    uint8_t* hash_value, uint8_t* fee,
                    secp256k1_gej* excess)
{
    if (parent_kernel)
    {
        // Nested kernel restrictions
        if ((kernel->kernel.min_height > parent_kernel->kernel.min_height)
            || (kernel->kernel.max_height < parent_kernel->kernel.max_height))
        {
            // Parent Height range must be contained in ours
            return 0;
        }
    }

    SHA256_CTX hp;
    sha256_Init(&hp);
    sha256_write_64(&hp, kernel->kernel.fee);
    sha256_write_64(&hp, kernel->kernel.min_height);
    sha256_write_64(&hp, kernel->kernel.max_height);
    sha256_Update(&hp, kernel->kernel.tx_element.commitment.x, DIGEST_LENGTH);
    sha256_write_8(&hp, kernel->kernel.tx_element.commitment.y);
    sha256_write_64(&hp, kernel->kernel.asset_emission);
    const uint8_t is_empty_kernel_hash_lock_preimage = memis0(kernel->kernel.hash_lock_preimage, DIGEST_LENGTH);
    const uint8_t is_non_empty_kernel_hash_lock_preimage = ! is_empty_kernel_hash_lock_preimage;
    sha256_write_8(&hp, is_non_empty_kernel_hash_lock_preimage);

    if (is_empty_kernel_hash_lock_preimage)
    {
        if (0)
        //if (hash_lock_preimage)
        {
            SHA256_CTX hash_lock_ctx;
            sha256_Update(&hash_lock_ctx, kernel->kernel.hash_lock_preimage, DIGEST_LENGTH);
            sha256_Final(&hash_lock_ctx, hash_value);
        }

        sha256_Update(&hp, hash_lock_preimage, DIGEST_LENGTH);
    }

    secp256k1_gej point_excess_nested;
    if (excess)
        secp256k1_gej_set_infinity(&point_excess_nested);

    const tx_kernel_t* zero_kernel = NULL;
    for (size_t i = 0; i < (size_t)kernel->nested_kernels.length; ++i)
    {
        const uint8_t should_break = 1;
        sha256_write_8(&hp, should_break);

        //TODO: to implement
        //const TxKernel& v = *(*it);
        //if (p0Krn && (*p0Krn > v))
        //    return false;
        //p0Krn = &v;

        //if (!v.Traverse(hv, pFee, pExcess ? &ptExcNested : NULL, this, NULL))
        //    return false;

        //hp << hv;
    }
    //TODO: Does this means that we extract from context?
    // hp >> hv
    sha256_Final(&hp, hash_value);

    if (excess)
    {
        //TODO
    }
    if (fee)
    {
        //TODO
    }

    return 1;
}

void kernel_get_hash(const tx_kernel_t* kernel, const uint8_t* hash_lock_preimage, uint8_t* out)
{
    kernel_traverse(kernel, NULL, hash_lock_preimage, out, NULL, NULL);
}

// 1st pass. Public excesses and Nonces are summed.
void cosign_kernel_part_1(tx_kernel_t* kernel,
                          secp256k1_gej* kG, secp256k1_gej* xG,
                          scalar_t* peer_scalars, scalar_t* peer_nonces, size_t num_peers,
                          scalar_t* transaction_offset, uint8_t* kernel_hash_message,
                          const uint8_t* hash_lock_preimage)
{
    for (size_t i = 0; i < num_peers; ++i)
    {
        peer_finalize_excess(&peer_scalars[i], kG, transaction_offset);

        // Nonces are initialized as a random buffer
        uint8_t random_scalar_data[DIGEST_LENGTH];
        //random_buffer(random_scalar_data, DIGEST_LENGTH);
        test_set_buffer(random_scalar_data, DIGEST_LENGTH, 3);
        scalar_set_b32(&peer_nonces[i], random_scalar_data, NULL);
        secp256k1_gej nonce_mul_g;
        generator_mul_scalar(&nonce_mul_g, get_context()->generator.G_pts, &peer_nonces[i]);
        secp256k1_gej_add_var(xG, xG, &nonce_mul_g, NULL);
    }

    for (size_t i = 0; i < (size_t)kernel->nested_kernels.length; ++i)
    {
        secp256k1_gej nested_point;
        point_import_nnz(&nested_point, &kernel->nested_kernels.data[i]->tx_element.commitment);
        //TODO: import
        //verify_test(ptNested.Import(krn.m_vNested[i]->m_Commitment));
        secp256k1_gej_add_var(kG, kG, &nested_point, NULL);
    }

    export_gej_to_point(kG, &kernel->kernel.tx_element.commitment);

    kernel_get_hash(kernel, hash_lock_preimage, kernel_hash_message);
}

// 2nd pass. Signing. Total excess is the signature public key.
void cosign_kernel_part_2(tx_kernel_t* kernel,
                          secp256k1_gej* xG,
                          scalar_t* peer_scalars, scalar_t* peer_nonces, size_t num_peers,
                          uint8_t* kernel_hash_message)
{
    scalar_t k_sig;
    scalar_set_int(&k_sig, 0);

    for (size_t i = 0; i < num_peers; ++i)
    {
        ecc_signature_t sig;
        sig.nonce_pub = *xG;

        scalar_t multisig_nonce = peer_nonces[i];

        scalar_t k;
        signature_sign_partial(&multisig_nonce, &sig.nonce_pub, kernel_hash_message, &peer_scalars[i], &k);
        scalar_add(&k_sig, &k_sig, &k);
        // Signed, prepare for next tx
        scalar_set_int(&peer_scalars[i], 0);
    }

    kernel->kernel.signature.nonce_pub = *xG;
    kernel->kernel.signature.k = k_sig;
}


void create_tx_kernel(tx_kernels_vec_t* trg_kernels,
                      tx_kernels_vec_t* nested_kernels,
                      uint64_t fee, uint32_t should_emit_custom_tag)
{
    tx_kernel_t* kernel = malloc(sizeof(tx_kernel_t));
    kernel->kernel.fee = fee;
    //TODO<Kirill A>: be careful to move data out of the vector
    memmove(kernel->nested_kernels.data, nested_kernels->data, nested_kernels->length * sizeof(tx_kernel_t));

    uint8_t preimage[DIGEST_LENGTH];
    //random_buffer(preimage, 32);
    test_set_buffer(preimage, DIGEST_LENGTH, 3);

    uint8_t lock_image[DIGEST_LENGTH];
    SHA256_CTX x;
    sha256_Init(&x);
    sha256_Update(&x, preimage, DIGEST_LENGTH);
    sha256_Final(&x, lock_image);

    if (should_emit_custom_tag)
    {
        uint8_t sk_asset_data[DIGEST_LENGTH];
        random_buffer(sk_asset_data, DIGEST_LENGTH);
        scalar_t sk_asset;
        scalar_import_nnz(&sk_asset, sk_asset_data);

        uint8_t aid[DIGEST_LENGTH];
        sk_to_pk(&sk_asset, get_context()->generator.G_pts, aid);

        uint64_t val_asset = 4431;

        //TODO<Kirill A>: do wee need this at all on Trezor?
        //if (beam::Rules::get().CA.Deposit)
        //    m_pPeers[0].AddInput(m_Trans, valAsset, m_Kdf); // input being-deposited

        //m_pPeers[0].AddOutput(m_Trans, valAsset, m_Kdf, &aid); // output UTXO to consume the created asset

        tx_kernel_t* kernel_emission = malloc(sizeof(tx_kernel_t));
        kernel_emission->kernel.asset_emission = val_asset;
        //TODO<Kirill A>: Why do we need these 2 following lines?!
        memcpy(kernel_emission->kernel.tx_element.commitment.x, aid, DIGEST_LENGTH);
        kernel_emission->kernel.tx_element.commitment.y = 0;

        secp256k1_gej commitment_native;
        generator_mul_scalar(&commitment_native, get_context()->generator.G_pts, &sk_asset);
        export_gej_to_point(&commitment_native, &kernel_emission->kernel.tx_element.commitment);

        vec_push(trg_kernels, kernel_emission);
        scalar_negate(&sk_asset, &sk_asset);

        //m_pPeers[0].m_k += skAsset;
    }

    //CoSignKernel(*pKrn, hvLockImage);

    //Point::Native exc;
    secp256k1_gej exc;
    // AmountBig::Type is 128 bits = 16 bytes
    //beam::AmountBig::Type fee2;
    uint8_t fee2[16];
    //verify_test(!pKrn->IsValid(fee2, exc)); // should not pass validation unless correct hash preimage is specified

    //// finish HL: add hash preimage
    //pKrn->m_pHashLock->m_Preimage = hlPreimage;
    memcpy(kernel->kernel.hash_lock_preimage, preimage, DIGEST_LENGTH);
    //verify_test(pKrn->IsValid(fee2, exc));

    vec_push(trg_kernels, kernel);
}
