#include "include/crypto.h"
#include "include/internal_types.h"

crypto_status_t rsa_encrypt_aes_key(crypto_ctx_t *ctx)
{
    crypto_status_t status = CRYPTO_ok;
    int32_t rsa_size = 0;
    int32_t encrypted_len = 0;

    if ((ctx == NULL) || (ctx->status != CRYPTO_ok))
    {
        status = CRYPTO_err;
    }

    if ((status == CRYPTO_ok) &&
        ((ctx->public_key.status != CRYPTO_ok) ||
         (ctx->pkg.aes_key.status != CRYPTO_ok)))
    {
        status = CRYPTO_err;
    }

    if (status == CRYPTO_ok)
    {
        rsa_size = wc_RsaEncryptSize(&ctx->public_key.key);
        if (rsa_size != (int32_t)RSA_MODULUS_BYTES)
        {
            status = CRYPTO_err;
        }
    }

    if (status == CRYPTO_ok)
    {
        (void)memset(&ctx->pkg.encrypted_aes_key, 0, sizeof(rsa_encrypted_t));
        ctx->pkg.encrypted_aes_key.status = CRYPTO_null;

        encrypted_len = wc_RsaPublicEncrypt_ex(
                            ctx->pkg.aes_key.key, sizeof(ctx->pkg.aes_key.key),
                            ctx->pkg.encrypted_aes_key.data, sizeof(ctx->pkg.encrypted_aes_key.data),
                            &ctx->public_key.key,
                            &ctx->rng,
                            WC_RSA_OAEP_PAD,
                            WC_HASH_TYPE_SHA256,
                            WC_MGF1SHA256,
                            NULL, 0u
                        );

        if (encrypted_len != (int32_t)RSA_MODULUS_BYTES)
        {
            status = CRYPTO_err;
        }
    }

    if (ctx != NULL)
    {
        if (status == CRYPTO_ok)
        {
            ctx->pkg.encrypted_aes_key.status = CRYPTO_ok;
        }
        else
        {
            ctx->pkg.encrypted_aes_key.status = CRYPTO_err;
            ctx->status = CRYPTO_err;
        }
    }

    return status;
}

crypto_status_t rsa_decrypt_aes_key(crypto_ctx_t *ctx)
{
    crypto_status_t status = CRYPTO_ok;
    int32_t rsa_size = 0;
    int32_t decrypted_len = 0;

    if ((ctx == NULL) || (ctx->status != CRYPTO_ok))
    {
        status = CRYPTO_err;
    }

    if ((status == CRYPTO_ok) &&
        ((ctx->private_key.status != CRYPTO_ok) ||
         (ctx->pkg.encrypted_aes_key.status != CRYPTO_ok)))
    {
        status = CRYPTO_err;
    }

    if (status == CRYPTO_ok)
    {
        rsa_size = wc_RsaEncryptSize(&ctx->private_key.key);
        if (rsa_size != (int32_t)RSA_MODULUS_BYTES)
        {
            status = CRYPTO_err;
        }
    }

    if (status == CRYPTO_ok)
    {
        (void)memset(&ctx->pkg.aes_key, 0, sizeof(aes_key_t));
        ctx->pkg.aes_key.status = CRYPTO_null;

        decrypted_len = wc_RsaPrivateDecrypt_ex(
                            ctx->pkg.encrypted_aes_key.data, sizeof(ctx->pkg.encrypted_aes_key.data),
                            ctx->pkg.aes_key.key, sizeof(ctx->pkg.aes_key.key),
                            &ctx->private_key.key,
                            WC_RSA_OAEP_PAD,
                            WC_HASH_TYPE_SHA256,
                            WC_MGF1SHA256,
                            NULL, 0u
                        );

        if (decrypted_len != (int32_t)AES_KEY_BYTES)
        {
            status = CRYPTO_err;
        }
    }

    if (ctx != NULL)
    {
        if (status == CRYPTO_ok)
        {
            ctx->pkg.aes_key.status = CRYPTO_ok;
        }
        else
        {
            ctx->pkg.aes_key.status = CRYPTO_err;
            ctx->status = CRYPTO_err;
        }
    }

    return status;
}