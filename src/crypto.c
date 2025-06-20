#include "include/crypto.h"
#include "include/internal_types.h"

crypto_status_t init_crypto_context(crypto_ctx_t *ctx)
{
    crypto_status_t status = CRYPTO_ok;
    int32_t rng_res = 0;

    if (ctx == NULL)
    {
        status = CRYPTO_err;
    }
    else
    {
        (void)memset(ctx, 0, sizeof(crypto_ctx_t));

        rng_res = wc_InitRng(&ctx->rng);
        if (rng_res != 0)
        {
            (void)wc_FreeRng(&ctx->rng);
            (void)memset(ctx, 0, sizeof(crypto_ctx_t));
            status = CRYPTO_err;
        }
        else
        {
            (void)memset(&ctx->pkg, 0, sizeof(encrypted_package_t));
            ctx->pkg.msg.status               = CRYPTO_null;
            ctx->pkg.encrypted_msg.status     = CRYPTO_null;
            ctx->pkg.aes_key.status           = CRYPTO_null;
            ctx->pkg.encrypted_aes_key.status = CRYPTO_null;
            ctx->pkg.aes_iv.status            = CRYPTO_null;
            ctx->pkg.signature.status         = CRYPTO_null;
            ctx->public_key.status            = CRYPTO_null;
            ctx->private_key.status           = CRYPTO_null;
        }
    }

    if (ctx != NULL)
    {
        if (status == CRYPTO_ok)
        {
            ctx->status = CRYPTO_ok;
        }
        else
        {
            ctx->status = CRYPTO_err;
        }
    }
    return status;
}

crypto_status_t free_crypto_context(crypto_ctx_t *ctx)
{
    crypto_status_t status = CRYPTO_ok;

    if (ctx == NULL)
    {
        status = CRYPTO_err;
    }
    else
    {
        (void)wc_FreeRng(&ctx->rng);
        if (ctx->public_key.status == CRYPTO_ok)
        {
            (void)wc_FreeRsaKey(&ctx->public_key.key);
            (void)wc_FreeRng(&ctx->public_key.rng);
        }
        if (ctx->private_key.status == CRYPTO_ok)
        {
            (void)wc_FreeRsaKey(&ctx->private_key.key);
            (void)wc_FreeRng(&ctx->private_key.rng);
        }
        (void)memset(ctx, 0, sizeof(crypto_ctx_t));
    }

    if (ctx != NULL)
    {
        ctx->status = CRYPTO_used;
    }
    return status;
}

crypto_status_t set_message(crypto_ctx_t *ctx, const uint8_t *in, uint32_t in_len)
{
    crypto_status_t status = CRYPTO_ok;
    uint32_t i = 0u;

    if ((ctx == NULL) || (ctx->status != CRYPTO_ok))
    {
        status = CRYPTO_err;
    }
    else if ((in == NULL) || (in_len > AES_MAX_MESSAGE_BYTES))
    {
        status = CRYPTO_err;
    }
    else
    {
        (void)memset(&ctx->pkg.msg, 0, sizeof(ctx->pkg.msg));
        ctx->pkg.msg.data_len = in_len;

        for (i = 0u; i < in_len; i++)
        {
            ctx->pkg.msg.data[i] = in[i];
        }
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

crypto_status_t encrypt_message( const uint8_t *in
                               ,       uint32_t in_size
                               ,       crypto_serialized_t *out
                               , const uint8_t *public_key
                               ,       uint32_t public_key_len
                               , const uint8_t *private_key
                               ,       uint32_t private_key_len
                               ,       crypto_ctx_t *ctx)
{

    crypto_status_t status = CRYPTO_null;
    uint32_t i = 0u;

    if ((ctx == NULL))
    {
        status = CRYPTO_err;
    }
    else if ((in == NULL) || (in_size > AES_MAX_MESSAGE_BYTES))
    {
        status = CRYPTO_err;
    }
    else if ((public_key == NULL) || (public_key_len > RSA_MAX_PUB_DER_KEY_BYTES))
    {
        status = CRYPTO_err;
    }
    else if ((private_key == NULL) || (private_key_len > RSA_MAX_PRV_DER_KEY_BYTES))
    {
        status = CRYPTO_err;
    }
    else
    {
        if (init_crypto_context(ctx) != CRYPTO_ok)
        {
            status = CRYPTO_INIT_err;
        }
        else if (set_message(ctx, in, in_size) != CRYPTO_ok)
        {
            status = CRYPTO_SET_MSG_err;
        }
        else if (set_rsa_public_key(public_key, public_key_len, ctx) != CRYPTO_ok)
        {
            status = CRYPTO_SET_PUB_KEY_err;
        }
        else if (set_rsa_private_key(private_key, private_key_len, ctx) != CRYPTO_ok)
        {
            status = CRYPTO_SET_PRV_KEY_err;
        }
        else if (generate_random_aes_key(ctx) != CRYPTO_ok)
        {
            status = CRYPTO_GEN_AES_KEY_err;
        }
        else if (generate_aes_iv(ctx) != CRYPTO_ok)
        {
            status = CRYPTO_GEN_AES_IV_err;
        }
        else if (aes_encrypt(ctx) != CRYPTO_ok)
        {
            status = CRYPTO_AES_ENCRYPT_err;
        }
        else if (rsa_encrypt_aes_key(ctx) != CRYPTO_ok)
        {
            status = CRYPTO_RSA_ENCRYPT_err;
        }
        else if (sign_message(ctx) != CRYPTO_ok)
        {
            status = CRYPTO_SIGN_MSG_err;
        }
        else if (serialize(out, ctx) != CRYPTO_ok)
        {
            status = CRYPTO_SERIALIZE_err;
        }
        else
        {
            status = CRYPTO_ok;
            (void)free_crypto_context(ctx);
        }
    }

    return status;
}

crypto_status_t decrypt_message( const uint8_t *in
                               ,       uint32_t in_size
                               ,       crypto_plain_message_t *out
                               , const uint8_t *public_key
                               ,       uint32_t public_key_len
                               , const uint8_t *private_key
                               ,       uint32_t private_key_len
                               ,       crypto_ctx_t *ctx)
{
    crypto_status_t status = CRYPTO_null;
    uint32_t i = 0u;

    if ((ctx == NULL))
    {
        status = CRYPTO_err;
    }
    else if ((in == NULL) || (in_size > SERIALIZED_DATA_SIZE))
    {
        status = CRYPTO_err;
    }
    else if ((public_key == NULL) || (public_key_len > RSA_MAX_PUB_DER_KEY_BYTES))
    {
        status = CRYPTO_err;
    }
    else if ((private_key == NULL) || (private_key_len > RSA_MAX_PRV_DER_KEY_BYTES))
    {
        status = CRYPTO_err;
    }
    else
    {
        if (init_crypto_context(ctx) != CRYPTO_ok)
        {
            status = CRYPTO_INIT_err;
        }
        else if (deserialize(in, in_size, ctx) != CRYPTO_ok)
        {
            status = CRYPTO_DESERIALIZE_err;
        }
        else if (set_rsa_public_key(public_key, public_key_len, ctx) != CRYPTO_ok)
        {
            status = CRYPTO_SET_PUB_KEY_err;
        }
        else if (set_rsa_private_key(private_key, private_key_len, ctx) != CRYPTO_ok)
        {
            status = CRYPTO_SET_PRV_KEY_err;
        }
        else if (rsa_decrypt_aes_key(ctx) != CRYPTO_ok)
        {
            status = CRYPTO_RSA_DECRYPT_err;
        }
        else if (aes_decrypt(ctx) != CRYPTO_ok)
        {
            status = CRYPTO_AES_DECRYPT_err;
        }
        else if (verify_signature(ctx) != CRYPTO_ok)
        {
            status = CRYPTO_VERIFY_MSG_err;
        }
        else
        {
            out->data_len = ctx->pkg.msg.data_len;
            for (i = 0u; i < out->data_len; i++)
            {
                out->data[i] = ctx->pkg.msg.data[i];
            }
            out->status = ctx->pkg.msg.status;
            (void)free_crypto_context(ctx);
            status = CRYPTO_ok;
        }
    }

    return status;
}