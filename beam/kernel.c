#include <string.h>

#include "internal.h"
#include "functions.h"
#include "../rand.h"


void kernel_push_back_moved(tx_kernels_vec_t* kernels, tx_kernel_t* kernel_to_push)
{
    tx_kernel_t* new_kernels = realloc(sizeof(tx_kernel_t) * (num_kernels + 1));
    if (!
    memmove(new_kernels, kernels, sizeof(tx_kernel_t) * num_kernels);
    memmove(new_kernels + sizeof(tx_kernel_t) * num_kernels, kernel_to_push, sizeof(tx_kernel_t));
    kernels = new_kernels;
}
void free_tx_kernels_vec(tx_kernels_vec_t* kernels)
{
    int i = 0;
    tx_kernel_t** kernel = NULL;
    vec_foreach_ptr(kernels, kernel, i) {
        // Get inner pointer and free it
        free(*kernel);
    }
    vec_deinit(kernels);
}

void create_tx_kernel(tx_kernels_vec_t* trg_kernels,
                      tx_kernels_vec_t* nested_kernels,
                      uint64_t fee, uint32_t should_emit_custom_tag)
{
    tx_kernel_t* kernel = malloc(sizeof(tx_kernel_t));
    kernel->fee = fee;
    //TODO<Kirill A>: be careful to move data out of the vector
    memmove(kernel->nested_kernels.data, nested_kernels->data, nested_kernels->length * sizeof(tx_kernel_t));

    uint8_t preimage[32];
    random_buffer(preimage, 32);

    uint8_t lock_image[32];
    SHA256_CTX x;
    sha256_Init(&x);
    sha256_Update(&x, preimage, 32);
    sha256_Final(&x, lock_image);

    if (should_emit_custom_tag)
    {
        uint8_t sk_asset_data[32];
        random_buffer(sk_asset_data, 32);
        scalar_t sk_asset;
        scalar_import_nnz(&sk_asset, sk_asset_data);

        uint8_t aid[32];
        sk_to_pk(&sk_asset, get_context()->generator.G_pts, aid);

        uint64_t val_asset = 4431;

        //TODO<Kirill A>: do wee need this at all on Trezor?
        //if (beam::Rules::get().CA.Deposit)
        //    m_pPeers[0].AddInput(m_Trans, valAsset, m_Kdf); // input being-deposited

        //m_pPeers[0].AddOutput(m_Trans, valAsset, m_Kdf, &aid); // output UTXO to consume the created asset

        tx_kernel_t* kernel_emission = malloc(sizeof(tx_kernel_t));
        kernel_emission.kernel.asset_emission = val_asset;
        //TODO<Kirill A>: Why do we need these 2 following lines?!
        memcpy(kernel_emission.kernel.tx_element.commitment.x, aid, 32);
        kernel_emission.kernel.tx_element.commitment.y = 0;

        secp256k1_gej commitment_native;
        generator_mul_scalar(&commitment_native, get_context()->generator.G_pts, &sk_asset);
        export_gej_to_point(&commitment_native, &kernel_emission.kernel.tx_element.commitment);

        vec_push(trg_kernels, kernel_emission);
        scalar_negate(&sk_asset, &sk_asset);

        //m_pPeers[0].m_k += skAsset;
    }

    //CoSignKernel(*pKrn, hvLockImage);


    //Point::Native exc;
    sec256k1_gej exc;
    // AmountBig::Type is 128 bits = 16 bytes
    //beam::AmountBig::Type fee2;
    uint8_t fee2[16];
    //verify_test(!pKrn->IsValid(fee2, exc)); // should not pass validation unless correct hash preimage is specified

    //// finish HL: add hash preimage
    //pKrn->m_pHashLock->m_Preimage = hlPreimage;
    memcpy(kernel->kernel.hash_lock_preimage, pre_image, 32);
    //verify_test(pKrn->IsValid(fee2, exc));

    //lstTrg.push_back(std::move(pKrn));
    vec_push(trg_kernels, kernel);
}
