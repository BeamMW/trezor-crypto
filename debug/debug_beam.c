#include <string.h>
#include <malloc.h>
#include <time.h>
#include "../beam/functions.h"
#include "base64.h"
#include "../beam/rangeproof.h"
#include "../beam/kernel.h"
#include "../beam/misc.h"
#include "../beam/inner_product.h"
#include "definitions_test.h"

#define VERIFY_TEST(x)                                                                                                        \
  do                                                                                                                          \
  {                                                                                                                           \
    if (!(x))                                                                                                                 \
      printf(ANSI_COLOR_RED "Test failed!" ANSI_COLOR_CYAN " Line=%u" ANSI_COLOR_RESET ", Expression: %s\n", __LINE__, #x);   \
    else                                                                                                                      \
      printf(ANSI_COLOR_GREEN "Test passed!" ANSI_COLOR_CYAN " Line=%u" ANSI_COLOR_RESET ", Expression: %s\n", __LINE__, #x); \
  } while (0)

#define VERIFY_TEST_EQUAL(x, msg, left_desc, right_desc)                                                                                     \
  do                                                                                                                          \
  {                                                                                                                           \
    if (!(x))                                                                                                                 \
      printf(ANSI_COLOR_RED "Test failed!" ANSI_COLOR_RESET ", %s. Expression: %s == %s\n", msg, left_desc, right_desc);   \
    else                                                                                                                      \
      printf(ANSI_COLOR_GREEN "Test passed!" ANSI_COLOR_RESET ", %s. Expression: %s == %s\n", msg, left_desc, right_desc); \
  } while (0)

#define VERIFY_TEST(x)                                                                                                        \
  do                                                                                                                          \
  {                                                                                                                           \
    if (!(x))                                                                                                                 \
      printf(ANSI_COLOR_RED "Test failed!" ANSI_COLOR_CYAN " Line=%u" ANSI_COLOR_RESET ", Expression: %s\n", __LINE__, #x);   \
    else                                                                                                                      \
      printf(ANSI_COLOR_GREEN "Test passed!" ANSI_COLOR_CYAN " Line=%u" ANSI_COLOR_RESET ", Expression: %s\n", __LINE__, #x); \
  } while (0)

void printAsBytes(const char *name, const void *mem, size_t len)
{
  uint8_t tmp[len];
  memcpy(tmp, mem, len);
  printf("const uint8_t %s[] = { ", name);
  for (size_t i = 0; i < len; i++)
  {
    if (i < len - 1)
      printf("0x%02x, ", tmp[i]);
    else
      printf("0x%02x };", tmp[i]);
  }
  printf("\n\n");
}

inline void hex2bin(const char *hex_string, const size_t size_string, uint8_t *out_bytes)
{
  uint32_t buffer = 0;
  for (size_t i = 0; i < size_string / 2; i++)
  {
    sscanf(hex_string + 2 * i, "%2X", &buffer);
    out_bytes[i] = buffer;
  }
}

int IS_EQUAL_HEX(const char *hex_str, const uint8_t *bytes, size_t str_size)
{
  uint8_t tmp[str_size / 2];
  hex2bin(hex_str, str_size, tmp);
  return memcmp(tmp, bytes, str_size / 2) == 0;
}

void verify_scalar_data(const char* msg, const char* hex_data, const scalar_t* sk)
{
    uint8_t sk_data[DIGEST_LENGTH];
    scalar_get_b32(sk_data, sk);
    DEBUG_PRINT(msg, sk_data, DIGEST_LENGTH);
    VERIFY_TEST_EQUAL(IS_EQUAL_HEX(hex_data, sk_data, DIGEST_LENGTH), msg, hex_data, "sk");
}

int test_tx_kernel(void)
{
    transaction_t transaction;
    transaction_init(&transaction);
    HKdf_t kdf;
    HKdf_init(&kdf);
    //DEBUG_PRINT("KDF: ", kdf.generator_secret, DIGEST_LENGTH);
    scalar_t peer_sk;
    scalar_clear(&peer_sk);

    // Test Add Input
    peer_add_input(&transaction.inputs, &peer_sk, 100, &kdf, NULL);
    verify_scalar_data("Peer sk data: ", "ce14a6bd640c284fc4c97f3eb2d8f99569c151bce08e0033f395814cb39b4d05", &peer_sk);
    peer_add_input(&transaction.inputs, &peer_sk, 3000, &kdf, NULL);
    peer_add_input(&transaction.inputs, &peer_sk, 2000, &kdf, NULL);
    verify_scalar_data("Peer sk data: ", "8b353049229348f3b04e841b7b8f19941303712b07acf9a90c0eaacd51fb3c98", &peer_sk);

    peer_add_output(&transaction.outputs, &peer_sk, 100, &kdf, NULL);//REALLY NULL?!
    verify_scalar_data("Peer sk data (after out): ", "bd20898bbe8720a3eb8504dcc8b61ffd63f0fc54d66799b0d84b880d6e9630d4", &peer_sk);

    DEBUG_PRINT("RP pub checksum:", transaction.outputs.data[0]->public_proof->recovery.checksum, 32);
    VERIFY_TEST(IS_EQUAL_HEX("654a4cac95b6654ee9c99c6a8a32236c8d06c1552c76b83f09c2f055325b2312",
                             transaction.outputs.data[0]->public_proof->recovery.checksum, 64));

    {
        SHA256_CTX rp_hash;
        uint8_t rp_digest[SHA256_DIGEST_LENGTH];
        sha256_Init(&rp_hash);
        sha256_Update(&rp_hash, (const uint8_t *)transaction.outputs.data[0]->confidential_proof, sizeof(rangeproof_confidential_t));
        sha256_Final(&rp_hash, rp_digest);
        DEBUG_PRINT("rangeproof confidential digest", rp_digest, SHA256_DIGEST_LENGTH);
    }

    uint64_t fee1 = 100;
    tx_kernel_t kernel;
    kernel_init(&kernel);
    kernel.kernel.fee = fee1;
    secp256k1_gej kG;
    secp256k1_gej xG;
    secp256k1_gej_set_infinity(&kG);
    secp256k1_gej_set_infinity(&xG);
    scalar_t peer_nonce;
    scalar_clear(&peer_nonce);
    uint8_t kernel_hash_message[DIGEST_LENGTH];

    uint8_t preimage[DIGEST_LENGTH];
    //random_buffer(preimage, 32);
    test_set_buffer(preimage, DIGEST_LENGTH, 3);

    uint8_t hash_lock_preimage[DIGEST_LENGTH];
    SHA256_CTX x;
    sha256_Init(&x);
    sha256_Update(&x, preimage, DIGEST_LENGTH);
    sha256_Final(&x, hash_lock_preimage);

    cosign_kernel_part_1(&kernel,
                         &kG, &xG,
                         &peer_sk, &peer_nonce, 1,
                         &transaction.offset, kernel_hash_message,
                         //TODO: Valdo said we have no hash lock in kernels currently
                         hash_lock_preimage);
    DEBUG_PRINT("Kernel commitment X: ", kernel.kernel.tx_element.commitment.x, DIGEST_LENGTH);
    printf("Kernel commitment Y: %u\n", kernel.kernel.tx_element.commitment.y);
    VERIFY_TEST(IS_EQUAL_HEX("531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337", kernel.kernel.tx_element.commitment.x, DIGEST_LENGTH * 2));
    VERIFY_TEST(kernel.kernel.tx_element.commitment.y == 1);
    verify_scalar_data("Transaction offset: ", "c0238c8ec18a23a6ee8807dfcbb9230066f3ff57d96a9cb3db4e8b10719933d7", &transaction.offset);
    DEBUG_PRINT("Hash lock msg: ", kernel_hash_message, DIGEST_LENGTH);
    VERIFY_TEST(IS_EQUAL_HEX("d729163b2cd6e4345f795d0b7341ef30cbd96d9c38bd2e6341f50519af9d7190", kernel_hash_message, DIGEST_LENGTH * 2));

    cosign_kernel_part_2(&kernel,
                         &xG,
                         &peer_sk, &peer_nonce, 1,
                         kernel_hash_message);
    verify_scalar_data("CoSignKernel - pt2. Sig sk: ", "ac0cdbf0769737e7cd3e2c36bf559f948c80236e8fac0fd713df65ca4eec8f67", &kernel.kernel.signature.k);

    transaction_free(&transaction);

    return 0;
}

void test_key_generation(void)
{
    key_idv_t kidv;
    key_idv_init(&kidv);
    kidv.value = 3;

    secp256k1_gej commitment;
    create_kidv_image(&kidv, &commitment, 1);

    point_t image;
    export_gej_to_point(&commitment, &image);
    DEBUG_PRINT("Generated key X:", image.x, DIGEST_LENGTH);
    printf("Generated key Y: %d\n", image.y);
    VERIFY_TEST(IS_EQUAL_HEX("tocalc", image.x, DIGEST_LENGTH));
}

void test_range_proof_confidential(void)
{
  const uint8_t asset_id[] = {0xcc, 0xb2, 0xcd, 0xc6, 0x9b, 0xb4, 0x54, 0x11, 0x0e, 0x82, 0x74, 0x41, 0x21, 0x3d, 0xdc, 0x87, 0x70, 0xe9, 0x3e, 0xa1, 0x41, 0xe1, 0xfc, 0x67, 0x3e, 0x01, 0x7e, 0x97, 0xea, 0xdc, 0x6b, 0x96};
  const uint8_t sk_bytes[] = {0x96, 0x6b, 0xdc, 0xea, 0x97, 0x7e, 0x01, 0x3e, 0x67, 0xfc, 0xe1, 0x41, 0xa1, 0x3e, 0xe9, 0x70, 0x87, 0xdc, 0x3d, 0x21, 0x41, 0x74, 0x82, 0x0e, 0x11, 0x54, 0xb4, 0x9b, 0xc6, 0xcd, 0xb2, 0xab};

  secp256k1_gej asset_tag_h_gen;
  switch_commitment(asset_id, &asset_tag_h_gen);
  uint8_t asset_first_32[32];
  memcpy(asset_first_32, &asset_tag_h_gen, 32);
  DEBUG_PRINT("asset_id", asset_first_32, 32);
  VERIFY_TEST(IS_EQUAL_HEX("2febca014feb9c00a1d961037119b90126b7a00071d6ec01fc388b00a4a75202", asset_first_32, 64));

  rangeproof_creator_params_t crp;
  memset(crp.seed, 1, 32);
  crp.kidv.value = 23110;
  crp.kidv.id.idx = 1;
  crp.kidv.id.type = 11;
  crp.kidv.id.sub_idx = 111;

  scalar_t sk;
  scalar_set_b32(&sk, sk_bytes, NULL);
  rangeproof_confidential_t rp;
  SHA256_CTX oracle;
  sha256_Init(&oracle);

  rangeproof_confidential_create(&rp, &sk, &crp, &oracle, &asset_tag_h_gen);

  SHA256_CTX rp_hash;
  uint8_t rp_digest[SHA256_DIGEST_LENGTH];
  sha256_Init(&rp_hash);
  sha256_Update(&rp_hash, (const uint8_t *)&rp, sizeof(rp));
  sha256_Final(&rp_hash, rp_digest);
  DEBUG_PRINT("rangeproof confidential digest", rp_digest, SHA256_DIGEST_LENGTH);
  VERIFY_TEST(IS_EQUAL_HEX("95d3d13d5c056f61461e57e13173cbfb82e2c24410d5ae72482537052c7db928", rp_digest, 64));
}

void test_range_proof_public(void)
{
  // Range proof
  const uint8_t asset_id[] = {0xcc, 0xb2, 0xcd, 0xc6, 0x9b, 0xb4, 0x54, 0x11, 0x0e, 0x82, 0x74, 0x41, 0x21, 0x3d, 0xdc, 0x87, 0x70, 0xe9, 0x3e, 0xa1, 0x41, 0xe1, 0xfc, 0x67, 0x3e, 0x01, 0x7e, 0x97, 0xea, 0xdc, 0x6b, 0x96};
  const uint8_t sk_bytes[] = {0x96, 0x6b, 0xdc, 0xea, 0x97, 0x7e, 0x01, 0x3e, 0x67, 0xfc, 0xe1, 0x41, 0xa1, 0x3e, 0xe9, 0x70, 0x87, 0xdc, 0x3d, 0x21, 0x41, 0x74, 0x82, 0x0e, 0x11, 0x54, 0xb4, 0x9b, 0xc6, 0xcd, 0xb2, 0xab};

  secp256k1_gej asset_tag_h_gen;
  switch_commitment(asset_id, &asset_tag_h_gen);
  uint8_t asset_first_32[32];
  memcpy(asset_first_32, &asset_tag_h_gen, 32);
  DEBUG_PRINT("asset_id", asset_first_32, 32);
  VERIFY_TEST(IS_EQUAL_HEX("2febca014feb9c00a1d961037119b90126b7a00071d6ec01fc388b00a4a75202", asset_first_32, 64));

  rangeproof_creator_params_t crp;
  memset(crp.seed, 1, 32);
  crp.kidv.value = 345000;
  crp.kidv.id.idx = 1;
  crp.kidv.id.type = 11;
  crp.kidv.id.sub_idx = 111;

  scalar_t sk;
  scalar_set_b32(&sk, sk_bytes, NULL);
  rangeproof_public_t rp;
  SHA256_CTX oracle;
  sha256_Init(&oracle);

  rangeproof_public_create(&rp, &sk, &crp, &oracle);
  DEBUG_PRINT("checksum:", rp.recovery.checksum, 32);
  VERIFY_TEST(IS_EQUAL_HEX("fb4c45f75b6bc159d0d17afd1700896c33eb3fb8b95d6c6a917dd34f2766e47d", rp.recovery.checksum, 64));

  uint8_t hash_value[32];
  secp256k1_gej pk;
  sha256_Init(&oracle);
  rangeproof_public_get_msg(&rp, hash_value, &oracle);
  generator_mul_scalar(&pk, get_context()->generator.G_pts, &sk);
  VERIFY_TEST(signature_is_valid(hash_value, &rp.signature, &pk, get_context()->generator.G_pts));

  secp256k1_gej comm;
  asset_tag_commit(&asset_tag_h_gen, &sk, crp.kidv.value, &comm);
  uint8_t comm_first_32[32];
  memcpy(comm_first_32, &comm, 32);
  DEBUG_PRINT("comm", comm_first_32, 32);
  VERIFY_TEST(IS_EQUAL_HEX("d5448218e78bc41b5ce49c1d2e6571183e55ff1ce2c1821c0ff0451be370971b", comm_first_32, 64));
}

void test_inner_product(void)
{
  scalar_t dot;
  scalar_t *pA = get_pa();
  scalar_t *pB = get_pb();
  inner_product_get_dot(&dot, pA, pB);

  uint8_t dot_bytes[sizeof(scalar_t)];
  memcpy(dot_bytes, &dot, sizeof(scalar_t));
  DEBUG_PRINT("inner_product dot", dot_bytes, sizeof(scalar_t));
  VERIFY_TEST(IS_EQUAL_HEX("6ff4ce5bb57f2907012b1eaf5b4b3f6ffc5a38bc0506ee25edfe621312c237de", dot_bytes, 64));

  inner_product_modifier_t mod;
  inner_product_modifier_init(&mod);
  mod.multiplier[1] = get_pwr_mul();

  secp256k1_gej comm;
  inner_product_t sig;
  SHA256_CTX oraclee;
  sha256_Init(&oraclee);
  inner_product_create(&sig, &oraclee, &comm, &dot, pA, pB, &mod);

  uint8_t comm_first_32[32];
  memcpy(comm_first_32, &comm, 32);
  DEBUG_PRINT("comm(pAB)", comm_first_32, 32);
  VERIFY_TEST(IS_EQUAL_HEX("7871671df832511da604b81cfb7de520b6bfd419c363cc1b41ab421b17e82d20", comm_first_32, 64));

  SHA256_CTX sig_hash;
  uint8_t sig_digest[SHA256_DIGEST_LENGTH];
  sha256_Init(&sig_hash);
  sha256_Update(&sig_hash, (const uint8_t *)&sig, sizeof(sig));
  sha256_Final(&sig_hash, sig_digest);
  DEBUG_PRINT("inner product sig digest", sig_digest, SHA256_DIGEST_LENGTH);
  VERIFY_TEST(IS_EQUAL_HEX("c7cdf73898af6edbda95be89e5f4a05a7da20cf5bcf71b9fbc409fffacfd273f", sig_digest, 64));
}

void test_common(void)
{
  uint8_t seed[DIGEST_LENGTH];
  phrase_to_seed("edge video genuine moon vibrant hybrid forum climb history iron involve sausage", seed);
  //phrase_to_seed("tomato provide age upon voice fetch nest night parent pilot evil furnace", seed);
  DEBUG_PRINT("sha256 of pbkdf2 of phrase: ", seed, DIGEST_LENGTH);
  VERIFY_TEST(IS_EQUAL_HEX("751b77ab415ed14573b150b66d779d429e48cd2a40c51bf6ce651ce6c38fd620", seed, 64));

  uint8_t secret_key[DIGEST_LENGTH];
  scalar_t cofactor;
  uint8_t cofactor_data[DIGEST_LENGTH];
  seed_to_kdf(seed, DIGEST_LENGTH, secret_key, &cofactor);
  scalar_get_b32(cofactor_data, &cofactor);
  DEBUG_PRINT("seed_to_kdf (gen / secret_key): ", secret_key, DIGEST_LENGTH);
  VERIFY_TEST(IS_EQUAL_HEX("d497d3d7dc9819a80e9035dd99d0877ebd61fd4cc7c19ee9a796c0aea6d04faf", secret_key, 64));
  DEBUG_PRINT("seed_to_kdf (coF): ", cofactor_data, DIGEST_LENGTH);
  VERIFY_TEST(IS_EQUAL_HEX("d6265c09c4ace3d6d01cb5528149fb0d751a2d5fa69172b67ee5cc9c1a320e73", cofactor_data, 64));

  uint8_t id[DIGEST_LENGTH];
  generate_hash_id(123456, get_context()->key.Bbs, 0, id);
  DEBUG_PRINT("generate_hash_id: ", id, DIGEST_LENGTH);
  VERIFY_TEST(IS_EQUAL_HEX("8d3a2b7de4c7757cdd8591a06db8c2d85dfec748ec598baaa5dc1ede8d171fd2", id, 64));

  scalar_t key;
  uint8_t key_data[DIGEST_LENGTH];
  derive_key(secret_key, DIGEST_LENGTH, id, DIGEST_LENGTH, &cofactor, &key);
  scalar_get_b32(key_data, &key);
  DEBUG_PRINT("derive_key (res): ", key_data, DIGEST_LENGTH);
  VERIFY_TEST(IS_EQUAL_HEX("1569368acd9ae88d2dd008643753312034c39c20d77ea27a5ac5091e9541d782", key_data, 64));

  uint8_t new_address_data[DIGEST_LENGTH];
  sk_to_pk(&key, get_context()->generator.G_pts, new_address_data);
  DEBUG_PRINT("sk_to_pk: ", new_address_data, DIGEST_LENGTH);
  VERIFY_TEST(IS_EQUAL_HEX("e27ba10a67f9b95140e2c6771df5b29674118832d3a51d2b79640370575538e4", new_address_data, 64));

  uint8_t msg[64];
  random_buffer(msg, 64);
  DEBUG_PRINT("generated message: ", msg, 64);

  point_t nonce_point;
  uint8_t k_data[DIGEST_LENGTH];
  ecc_signature_t signature;
  signature_sign(msg, &key, get_context()->generator.G_pts, &signature);
  scalar_get_b32(k_data, &signature.k);
  export_gej_to_point(&signature.nonce_pub, &nonce_point);
  DEBUG_PRINT("signature_sign k: ", k_data, DIGEST_LENGTH);
  DEBUG_PRINT("signature_sign nonce_point.x: ", nonce_point.x, DIGEST_LENGTH);

  secp256k1_gej pk;
  generator_mul_scalar(&pk, get_context()->generator.G_pts, &key);
  VERIFY_TEST(signature_is_valid(msg, &signature, &pk, get_context()->generator.G_pts)); // passed
  msg[0]++;
  VERIFY_TEST(!signature_is_valid(msg, &signature, &pk, get_context()->generator.G_pts)); // failed

  uint8_t *owner_key = get_owner_key(secret_key, &cofactor, (uint8_t *)"qwerty", 7);
  char *owner_key_encoded = b64_encode(owner_key, 108);
  printf("owner_key encoded:" ANSI_COLOR_YELLOW " %s\n" ANSI_COLOR_RESET, owner_key_encoded);
  VERIFY_TEST(0 == strncmp("mJrVrOiyjaMFCjxRsfGahBkiVzC+ymIXDv2qJdJxR4WMBY4rCJ+vTkkcCdVXw41p", owner_key_encoded, 64));
  free(owner_key);
  free(owner_key_encoded);
}

int main(void)
{
  random_reseed(time(NULL));
  init_context();

  test_common();
  test_inner_product();
  test_range_proof_public();
  test_range_proof_confidential();
  test_tx_kernel();
  test_key_generation();

  free_context();
  malloc_stats();

  return 0;
}
