#include "../include/crypto.h"
#include "../include/internal_types.h"

crypto_status_t generate_aes_key(uint8_t ok_bits, crypto_ctx_t *ctx)
{
    crypto_status_t status = CRYPTO_ok;
    int32_t rng_res = 0;

    if ((ctx == NULL) || (ctx->status != CRYPTO_ok))
    {
        status = CRYPTO_err;
    }
    if (status == CRYPTO_ok)
    {
        (void)memset(&ctx->pkg.aes_key, 0, sizeof(aes_key_t));
        ctx->pkg.aes_key.key[0] = ok_bits;
        rng_res = wc_RNG_GenerateBlock(&ctx->rng,
                    &ctx->pkg.aes_key.key[AES_OK_OFFSET_BYTES],
                    (sizeof(ctx->pkg.aes_key.key) - AES_OK_OFFSET_BYTES));
        if (rng_res != 0)
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

crypto_status_t generate_random_aes_key(crypto_ctx_t *ctx)
{
    crypto_status_t status = CRYPTO_ok;
    int32_t rng_res = 0;

    if ((ctx == NULL) || (ctx->status != CRYPTO_ok))
    {
        status = CRYPTO_err;
    }
    if (status == CRYPTO_ok)
    {
        (void)memset(&ctx->pkg.aes_key, 0, sizeof(aes_key_t));
        rng_res = wc_RNG_GenerateBlock(&ctx->rng,
                    ctx->pkg.aes_key.key,
                    sizeof(ctx->pkg.aes_key.key));
        if (rng_res != 0)
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

crypto_status_t generate_aes_iv(crypto_ctx_t *ctx)
{
    crypto_status_t status = CRYPTO_ok;
    int32_t rng_res = 0;

    if ((ctx == NULL) || (ctx->status != CRYPTO_ok))
    {
        status = CRYPTO_err;
    }
    if (status == CRYPTO_ok)
    {
        (void)memset(&ctx->pkg.aes_iv, 0, sizeof(aes_iv_t));
        rng_res = wc_RNG_GenerateBlock(&ctx->rng,
                    ctx->pkg.aes_iv.iv,
                    sizeof(ctx->pkg.aes_iv.iv));
        if (rng_res != 0)
        {
            status = CRYPTO_err;
        }
    }
    if (ctx != NULL)
    {
        if (status == CRYPTO_ok)
        {
            ctx->pkg.aes_iv.status = CRYPTO_ok;
        }
        else
        {
            ctx->pkg.aes_iv.status = CRYPTO_err;
            ctx->status = CRYPTO_err;
        }
    }
    return status;
}

crypto_status_t aes_encrypt(crypto_ctx_t *ctx)
{
    crypto_status_t status = CRYPTO_ok;
    Aes aes = { 0 };
    int32_t aes_init_res = 0;
    int32_t aes_set_key_res = 0;
    int32_t aes_encrypt_res = 0;

    if ((ctx == NULL) || (ctx->status != CRYPTO_ok))
    {
        status = CRYPTO_err;
    }
    if (status == CRYPTO_ok)
    {
        if ((ctx->pkg.aes_key.status != CRYPTO_ok) ||
            (ctx->pkg.aes_iv.status != CRYPTO_ok)  ||
            (ctx->pkg.msg.status != CRYPTO_ok)     ||
            (ctx->pkg.msg.data_len == 0u))
        {
            status = CRYPTO_err;
        }
    }
    if (status == CRYPTO_ok)
    {
        (void)memset(&ctx->pkg.encrypted_msg, 0, sizeof(encrypted_message_t));
        aes = (Aes){ 0 };
        aes_init_res = wc_AesInit(&aes, NULL, INVALID_DEVID);
        if (aes_init_res != 0)
        {
            status = CRYPTO_err;
        }
        else
        {
            aes_set_key_res = wc_AesGcmSetKey(&aes,
                                ctx->pkg.aes_key.key,
                                sizeof(ctx->pkg.aes_key.key));
            if (aes_set_key_res != 0)
            {
                status = CRYPTO_err;
            }
            else
            {
                aes_encrypt_res = wc_AesGcmEncrypt(&aes,
                                    ctx->pkg.encrypted_msg.data,
                                    ctx->pkg.msg.data,
                                    ctx->pkg.msg.data_len,
                                    ctx->pkg.aes_iv.iv,
                                    sizeof(ctx->pkg.aes_iv.iv),
                                    ctx->pkg.encrypted_msg.tag,
                                    sizeof(ctx->pkg.encrypted_msg.tag),
                                    NULL, 0u);
                if (aes_encrypt_res != 0)
                {
                    status = CRYPTO_err;
                }
                else
                {
                    ctx->pkg.encrypted_msg.data_len = ctx->pkg.msg.data_len;
                }
            }
        }
        wc_AesFree(&aes);
    }
    if (ctx != NULL)
    {
        if (status == CRYPTO_ok)
        {
            ctx->pkg.encrypted_msg.status = CRYPTO_ok;
            /* Mark the IV as used after encryption */
            ctx->pkg.aes_iv.status = CRYPTO_used;
        }
        else
        {
            ctx->pkg.encrypted_msg.status = CRYPTO_err;
            ctx->status = CRYPTO_err;
        }
    }
    return status;
}

crypto_status_t aes_decrypt(crypto_ctx_t *ctx)
{
    crypto_status_t status = CRYPTO_ok;
    Aes aes = { 0 };
    int32_t aes_init_res = 0;
    int32_t aes_set_key_res = 0;
    int32_t aes_decrypt_res = 0;

    if ((ctx == NULL) || (ctx->status != CRYPTO_ok))
    {
        status = CRYPTO_err;
    }
    if (status == CRYPTO_ok)
    {
        if ((ctx->pkg.aes_key.status != CRYPTO_ok) ||
            (ctx->pkg.aes_iv.status != CRYPTO_used)  ||
            (ctx->pkg.encrypted_msg.status != CRYPTO_ok) ||
            (ctx->pkg.encrypted_msg.data_len == 0u))
        {
            status = CRYPTO_err;
        }
    }
    if (status == CRYPTO_ok)
    {
        (void)memset(&ctx->pkg.msg, 0, sizeof(crypto_plain_message_t));
        aes = (Aes){ 0 };
        aes_init_res = wc_AesInit(&aes, NULL, INVALID_DEVID);
        if (aes_init_res != 0)
        {
            status = CRYPTO_err;
        }
        else
        {
            aes_set_key_res = wc_AesGcmSetKey(&aes,
                                ctx->pkg.aes_key.key,
                                sizeof(ctx->pkg.aes_key.key));
            if (aes_set_key_res != 0)
            {
                status = CRYPTO_err;
            }
            else
            {
                aes_decrypt_res = wc_AesGcmDecrypt(&aes,
                                    ctx->pkg.msg.data,
                                    ctx->pkg.encrypted_msg.data,
                                    ctx->pkg.encrypted_msg.data_len,
                                    ctx->pkg.aes_iv.iv,
                                    sizeof(ctx->pkg.aes_iv.iv),
                                    ctx->pkg.encrypted_msg.tag,
                                    sizeof(ctx->pkg.encrypted_msg.tag),
                                    NULL, 0u);
                if (aes_decrypt_res != 0)
                {
                    status = CRYPTO_err;
                }
                else
                {
                    ctx->pkg.msg.data_len = ctx->pkg.encrypted_msg.data_len;
                }
            }
        }
        wc_AesFree(&aes);
    }
    if (ctx != NULL)
    {
        if (status == CRYPTO_ok)
        {
            ctx->pkg.msg.status = CRYPTO_ok;
        }
        else
        {
            ctx->pkg.msg.status = CRYPTO_err;
            ctx->status = CRYPTO_err;
        }
    }
    return status;
}