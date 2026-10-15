#include "r_sce.h"
#include <string.h>

#define SYSTEM_PRCR (*(volatile uint16_t *) 0x4001E3FEUL)
#define SYSTEM_PRCR_KEY 0xA500U
#define SYSTEM_PRCR_SAR 0x0008U

void R_BSP_RegisterProtectDisable(bsp_reg_protect_t protect)
{
    if (protect == BSP_REG_PROTECT_SAR) {
        SYSTEM_PRCR = SYSTEM_PRCR_KEY | SYSTEM_PRCR_SAR;
    }
}

void R_BSP_RegisterProtectEnable(bsp_reg_protect_t protect)
{
    if (protect == BSP_REG_PROTECT_SAR) {
        SYSTEM_PRCR = SYSTEM_PRCR_KEY;
    }
}

static sce_instance_ctrl_t g_sce_ctrl;
static const sce_cfg_t g_sce_cfg;

_Static_assert(sizeof(sce_aes_wrapped_key_t) == 68, "unexpected SCE9 AES key ABI");
_Static_assert(sizeof(sce_ecc_private_wrapped_key_t) == 72, "unexpected SCE9 ECC private key ABI");
_Static_assert(sizeof(sce_ecc_public_wrapped_key_t) == 120, "unexpected SCE9 ECC public key ABI");
_Static_assert(sizeof(sce_ecc_wrapped_pair_key_t) == 192, "unexpected SCE9 ECC pair ABI");
_Static_assert(sizeof(sce_ecdh_wrapped_key_t) == 56, "unexpected SCE9 ECDH secret ABI");
_Static_assert(sizeof(sce_sha_md5_handle_t) == 176, "unexpected SCE9 SHA handle ABI");

extern uint32_t g_sha256_private_id;

static void wipe(void * pointer, uint32_t length)
{
    volatile uint8_t * bytes = pointer;
    while (length-- != 0) {
        *bytes++ = 0;
    }
}

uint32_t krabitls_sce9_open(void)
{
    return R_SCE_Open(&g_sce_ctrl, &g_sce_cfg);
}

uint32_t krabitls_sce9_close(void)
{
    return R_SCE_Close(&g_sce_ctrl);
}

uint32_t krabitls_sce9_reset(void)
{
    return R_SCE_SoftwareReset();
}

uint32_t krabitls_sce9_random(uint8_t * output, uint32_t length)
{
    uint32_t words[4];
    while (length != 0) {
        fsp_err_t status = R_SCE_RandomNumberGenerate(words);
        if (status != FSP_SUCCESS) {
            wipe(words, sizeof(words));
            return status;
        }
        uint32_t take = length < sizeof(words) ? length : sizeof(words);
        memcpy(output, words, take);
        output += take;
        length -= take;
    }
    wipe(words, sizeof(words));
    return FSP_SUCCESS;
}

uint32_t krabitls_sce9_sha256(const uint8_t * message, uint32_t length, uint8_t output[32])
{
    sce_sha_md5_handle_t handle;
    uint32_t output_length = 0;
    fsp_err_t status = R_SCE_SHA256_Init(&handle);
    if (status == FSP_SUCCESS) {
        status = R_SCE_SHA256_Update(&handle, (uint8_t *) message, length);
    }
    if (status == FSP_SUCCESS) {
        status = R_SCE_SHA256_Final(&handle, output, &output_length);
    }
    wipe(&handle, sizeof(handle));
    if (status == FSP_SUCCESS && output_length != 32) {
        wipe(output, 32);
        return FSP_ERR_CRYPTO_SCE_FAIL;
    }
    return status;
}

uint32_t krabitls_sce9_sha256_init(uint8_t state[176])
{
    return R_SCE_SHA256_Init((sce_sha_md5_handle_t *) state);
}

uint32_t krabitls_sce9_sha256_update(uint8_t state[176], const uint8_t * message, uint32_t length)
{
    sce_sha_md5_handle_t * handle = (sce_sha_md5_handle_t *) state;
    uint32_t words[16];
    /* FSP uses this global as an anti-interleave guard. Restore the cloned
     * handle's ID so TLS transcript snapshots can resume independently. */
    g_sha256_private_id = handle->id;
    while (length != 0) {
        uint32_t take = length < sizeof(words) ? length : sizeof(words);
        memcpy(words, message, take);
        fsp_err_t status = R_SCE_SHA256_Update(handle, (uint8_t *) words, take);
        wipe(words, sizeof(words));
        if (status != FSP_SUCCESS) {
            return status;
        }
        message += take;
        length -= take;
    }
    return FSP_SUCCESS;
}

uint32_t krabitls_sce9_sha256_snapshot(const uint8_t state[176], uint8_t output[32])
{
    sce_sha_md5_handle_t snapshot;
    uint32_t output_length = 0;
    memcpy(&snapshot, state, sizeof(snapshot));
    /* See the cloned-handle synchronization in the update path above. */
    g_sha256_private_id = snapshot.id;
    fsp_err_t status = R_SCE_SHA256_Final(&snapshot, output, &output_length);
    wipe(&snapshot, sizeof(snapshot));
    if (status == FSP_SUCCESS && output_length != 32) {
        wipe(output, 32);
        return FSP_ERR_CRYPTO_SCE_FAIL;
    }
    return status;
}

uint32_t krabitls_sce9_aes128_generate(uint8_t wrapped_key[68])
{
    return R_SCE_AES128_WrappedKeyGenerate((sce_aes_wrapped_key_t *) wrapped_key);
}

static uint32_t gcm_encrypt_chunks(sce_gcm_handle_t * handle,
                                   const uint8_t * input,
                                   uint8_t * output,
                                   uint32_t length,
                                   const uint8_t * aad,
                                   uint32_t aad_length,
                                   uint8_t tag[16])
{
    uint32_t in_words[4];
    uint32_t out_words[4];
    uint32_t zero_words[4] = { 0 };
    fsp_err_t status = FSP_SUCCESS;

    while (aad_length != 0 && status == FSP_SUCCESS) {
        uint32_t take = aad_length < 16 ? aad_length : 16;
        memset(in_words, 0, sizeof(in_words));
        memcpy(in_words, aad, take);
        status = R_SCE_AES128GCM_EncryptUpdate(handle, (uint8_t *) zero_words,
                                               (uint8_t *) out_words, 0,
                                               (uint8_t *) in_words, take);
        aad += take;
        aad_length -= take;
    }
    while (length != 0 && status == FSP_SUCCESS) {
        uint32_t take = length < 16 ? length : 16;
        memset(in_words, 0, sizeof(in_words));
        memset(out_words, 0, sizeof(out_words));
        memcpy(in_words, input, take);
        status = R_SCE_AES128GCM_EncryptUpdate(handle, (uint8_t *) in_words,
                                               (uint8_t *) out_words, take,
                                               (uint8_t *) zero_words, 0);
        if (status == FSP_SUCCESS && take == 16) {
            memcpy(output, out_words, 16);
        }
        input += take;
        output += take;
        length -= take;
    }
    if (status == FSP_SUCCESS) {
        uint32_t final_length = 0;
        memset(out_words, 0, sizeof(out_words));
        status = R_SCE_AES128GCM_EncryptFinal(handle, (uint8_t *) out_words,
                                              &final_length, tag);
        if (status == FSP_SUCCESS && (final_length & 15U) != 0) {
            memcpy(output - (final_length & 15U), out_words, final_length & 15U);
        }
    }
    wipe(in_words, sizeof(in_words));
    wipe(out_words, sizeof(out_words));
    return status;
}

uint32_t krabitls_sce9_aes128_gcm_encrypt(const uint8_t wrapped_key[68],
                                          const uint8_t nonce[12],
                                          const uint8_t * aad,
                                          uint32_t aad_length,
                                          const uint8_t * input,
                                          uint8_t * output,
                                          uint32_t length,
                                          uint8_t tag[16])
{
    sce_gcm_handle_t handle;
    uint32_t nonce_words[3];
    memcpy(nonce_words, nonce, sizeof(nonce_words));
    fsp_err_t status = R_SCE_AES128GCM_EncryptInit(&handle,
        (sce_aes_wrapped_key_t *) wrapped_key, (uint8_t *) nonce_words, 12);
    if (status == FSP_SUCCESS) {
        status = gcm_encrypt_chunks(&handle, input, output, length, aad, aad_length, tag);
    }
    if (status != FSP_SUCCESS) {
        wipe(output, length);
        wipe(tag, 16);
    }
    wipe(&handle, sizeof(handle));
    wipe(nonce_words, sizeof(nonce_words));
    return status;
}

static uint32_t gcm_decrypt_chunks(sce_gcm_handle_t * handle,
                                   const uint8_t * input,
                                   uint8_t * output,
                                   uint32_t length,
                                   const uint8_t * aad,
                                   uint32_t aad_length,
                                   const uint8_t tag[16])
{
    uint32_t in_words[4];
    uint32_t out_words[4];
    uint32_t zero_words[4] = { 0 };
    fsp_err_t status = FSP_SUCCESS;
    uint32_t total = length;
    uint8_t * output_start = output;

    while (aad_length != 0 && status == FSP_SUCCESS) {
        uint32_t take = aad_length < 16 ? aad_length : 16;
        memset(in_words, 0, sizeof(in_words));
        memcpy(in_words, aad, take);
        status = R_SCE_AES128GCM_DecryptUpdate(handle, (uint8_t *) zero_words,
                                               (uint8_t *) out_words, 0,
                                               (uint8_t *) in_words, take);
        aad += take;
        aad_length -= take;
    }
    while (length != 0 && status == FSP_SUCCESS) {
        uint32_t take = length < 16 ? length : 16;
        memset(in_words, 0, sizeof(in_words));
        memset(out_words, 0, sizeof(out_words));
        memcpy(in_words, input, take);
        status = R_SCE_AES128GCM_DecryptUpdate(handle, (uint8_t *) in_words,
                                               (uint8_t *) out_words, take,
                                               (uint8_t *) zero_words, 0);
        if (status == FSP_SUCCESS && take == 16) {
            memcpy(output, out_words, 16);
        }
        input += take;
        output += take;
        length -= take;
    }
    if (status == FSP_SUCCESS) {
        uint32_t final_length = 0;
        memset(out_words, 0, sizeof(out_words));
        memcpy(in_words, tag, 16);
        status = R_SCE_AES128GCM_DecryptFinal(handle, (uint8_t *) out_words,
                                              &final_length, (uint8_t *) in_words, 16);
        if (status == FSP_SUCCESS && (final_length & 15U) != 0) {
            memcpy(output - (final_length & 15U), out_words, final_length & 15U);
        }
    }
    if (status != FSP_SUCCESS) {
        wipe(output_start, total);
    }
    wipe(in_words, sizeof(in_words));
    wipe(out_words, sizeof(out_words));
    return status;
}

uint32_t krabitls_sce9_aes128_gcm_decrypt(const uint8_t wrapped_key[68],
                                          const uint8_t nonce[12],
                                          const uint8_t * aad,
                                          uint32_t aad_length,
                                          const uint8_t * input,
                                          uint8_t * output,
                                          uint32_t length,
                                          const uint8_t tag[16])
{
    sce_gcm_handle_t handle;
    uint32_t nonce_words[3];
    memcpy(nonce_words, nonce, sizeof(nonce_words));
    fsp_err_t status = R_SCE_AES128GCM_DecryptInit(&handle,
        (sce_aes_wrapped_key_t *) wrapped_key, (uint8_t *) nonce_words, 12);
    if (status == FSP_SUCCESS) {
        status = gcm_decrypt_chunks(&handle, input, output, length, aad, aad_length, tag);
    }
    if (status != FSP_SUCCESS) {
        wipe(output, length);
    }
    wipe(&handle, sizeof(handle));
    wipe(nonce_words, sizeof(nonce_words));
    return status;
}

uint32_t krabitls_sce9_p256_generate(uint8_t pair[192], uint8_t public_key[64])
{
    sce_ecc_wrapped_pair_key_t * key = (sce_ecc_wrapped_pair_key_t *) pair;
    fsp_err_t status = R_SCE_ECC_secp256r1_WrappedKeyPairGenerate(key);
    if (status == FSP_SUCCESS) {
        memcpy(public_key, key->pub_key.value.key_q, 64);
    } else {
        wipe(pair, 192);
        wipe(public_key, 64);
    }
    return status;
}

uint32_t krabitls_sce9_p256_ecdh_generate(const uint8_t signing_pair[192],
                                          uint8_t ecdh_handle[20],
                                          uint8_t ephemeral_private[72],
                                          uint8_t public_key[64],
                                          uint8_t public_signature[64])
{
    const sce_ecc_wrapped_pair_key_t * signer =
        (const sce_ecc_wrapped_pair_key_t *) signing_pair;
    sce_ecdh_handle_t * handle = (sce_ecdh_handle_t *) ecdh_handle;
    uint32_t signature_words[16];
    sce_ecdsa_byte_data_t signature = { (uint8_t *) signature_words, 64, 0 };
    fsp_err_t status = R_SCE_ECDH_secp256r1_Init(handle, 0, 0);
    if (status == FSP_SUCCESS) {
        status = R_SCE_ECDH_secp256r1_PublicKeySign(handle, 0,
            (sce_ecc_private_wrapped_key_t *) &signer->priv_key,
            public_key, &signature,
            (sce_ecc_private_wrapped_key_t *) ephemeral_private);
    }
    if (status == FSP_SUCCESS) {
        memcpy(public_signature, signature_words, 64);
    }
    wipe(signature_words, sizeof(signature_words));
    if (status != FSP_SUCCESS) {
        wipe(ecdh_handle, 20);
        wipe(ephemeral_private, 72);
        wipe(public_key, 64);
        wipe(public_signature, 64);
    }
    return status;
}

uint32_t krabitls_sce9_p256_ecdh_authenticated(uint8_t ecdh_handle[20],
                                               const uint8_t ephemeral_private[72],
                                               const uint8_t peer_public[64],
                                               const uint8_t peer_signature[64],
                                               const uint8_t peer_signing_pair[192],
                                               uint8_t wrapped_secret[56])
{
    const sce_ecc_wrapped_pair_key_t * signer =
        (const sce_ecc_wrapped_pair_key_t *) peer_signing_pair;
    sce_ecc_public_wrapped_key_t peer;
    sce_ecdh_handle_t * handle = (sce_ecdh_handle_t *) ecdh_handle;
    sce_ecdsa_byte_data_t signature = { (uint8_t *) peer_signature, 64, 0 };
    fsp_err_t status = R_SCE_ECDH_secp256r1_PublicKeyVerify(handle,
        (sce_ecc_public_wrapped_key_t *) &signer->pub_key,
        (uint8_t *) peer_public, &signature, &peer);
    if (status == FSP_SUCCESS) {
        status = R_SCE_ECDH_secp256r1_SharedSecretCalculate(handle, &peer,
            (sce_ecc_private_wrapped_key_t *) ephemeral_private,
            (sce_ecdh_wrapped_key_t *) wrapped_secret);
    }
    wipe(&peer, sizeof(peer));
    if (status != FSP_SUCCESS) {
        wipe(ecdh_handle, 20);
        wipe(wrapped_secret, 56);
    }
    return status;
}

uint32_t krabitls_sce9_p256_ecdh_ephemeral(uint8_t ecdh_handle[20],
                                           const uint8_t ephemeral_private[72],
                                           const uint8_t peer_public[64],
                                           uint8_t wrapped_secret[56])
{
    sce_ecc_public_wrapped_key_t peer;
    sce_ecdh_handle_t * handle = (sce_ecdh_handle_t *) ecdh_handle;
    fsp_err_t status = R_SCE_ECDH_secp256r1_PublicKeyReadWithoutSignature(handle,
        (uint8_t *) peer_public, &peer);
    if (status == FSP_SUCCESS) {
        status = R_SCE_ECDH_secp256r1_SharedSecretCalculate(handle, &peer,
            (sce_ecc_private_wrapped_key_t *) ephemeral_private,
            (sce_ecdh_wrapped_key_t *) wrapped_secret);
    }
    wipe(&peer, sizeof(peer));
    if (status != FSP_SUCCESS) {
        wipe(ecdh_handle, 20);
        wipe(wrapped_secret, 56);
    }
    return status;
}

uint32_t krabitls_sce9_p256_ecdh_derive_aes128(uint8_t ecdh_handle[20],
                                               const uint8_t wrapped_secret[56],
                                               const uint8_t * other_info,
                                               uint32_t other_info_length,
                                               uint8_t wrapped_key[68])
{
    sce_ecdh_handle_t * handle = (sce_ecdh_handle_t *) ecdh_handle;
    fsp_err_t status = R_SCE_ECDH_secp256r1_KeyDerivation(handle,
        (sce_ecdh_wrapped_key_t *) wrapped_secret, 0, 0,
        (uint8_t *) other_info, other_info_length, 0,
        (sce_aes_wrapped_key_t *) wrapped_key);
    wipe(ecdh_handle, 20);
    if (status != FSP_SUCCESS) {
        wipe(wrapped_key, 68);
    }
    return status;
}

uint32_t krabitls_sce9_p256_sign_hash(const uint8_t pair[192],
                                      const uint8_t hash[32],
                                      uint8_t signature[64])
{
    const sce_ecc_wrapped_pair_key_t * key = (const sce_ecc_wrapped_pair_key_t *) pair;
    sce_ecdsa_byte_data_t digest = { (uint8_t *) hash, 32, 1 };
    sce_ecdsa_byte_data_t sig = { signature, 64, 0 };
    fsp_err_t status = R_SCE_ECDSA_secp256r1_SignatureGenerate(&digest, &sig,
        (sce_ecc_private_wrapped_key_t *) &key->priv_key);
    if (status != FSP_SUCCESS || sig.data_length != 64) {
        wipe(signature, 64);
        return status == FSP_SUCCESS ? FSP_ERR_CRYPTO_SCE_FAIL : status;
    }
    return FSP_SUCCESS;
}

uint32_t krabitls_sce9_p256_verify_hash(const uint8_t pair[192],
                                        const uint8_t hash[32],
                                        const uint8_t signature[64])
{
    const sce_ecc_wrapped_pair_key_t * key = (const sce_ecc_wrapped_pair_key_t *) pair;
    sce_ecdsa_byte_data_t digest = { (uint8_t *) hash, 32, 1 };
    sce_ecdsa_byte_data_t sig = { (uint8_t *) signature, 64, 0 };
    return R_SCE_ECDSA_secp256r1_SignatureVerify(&sig, &digest,
        (sce_ecc_public_wrapped_key_t *) &key->pub_key);
}
