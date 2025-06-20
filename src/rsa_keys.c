#include "../include/crypto.h"
#include "../include/internal_types.h"

crypto_status_t set_rsa_public_key(const uint8_t *in, uint32_t in_len, crypto_ctx_t *ctx)
{
    crypto_status_t status = CRYPTO_ok;
    uint32_t idx = 0u;
    int32_t result = 0;

    if ((ctx == NULL) || (ctx->status != CRYPTO_ok))
    {
        status = CRYPTO_err;
    }

    if ((status == CRYPTO_ok) &&
        ((in == NULL) || (in_len > (uint32_t)RSA_MAX_PUB_DER_KEY_BYTES)))
    {
        status = CRYPTO_err;
    }

    if (status == CRYPTO_ok)
    {
        if (ctx->public_key.status == CRYPTO_ok)
        {
            (void)wc_FreeRsaKey(&ctx->public_key.key);
            (void)wc_FreeRng(&ctx->public_key.rng);
        }

        (void)memset(&ctx->public_key, 0, sizeof(rsa_key_t));
        ctx->public_key.key = (RsaKey){0};
        ctx->public_key.status = CRYPTO_null;

        result = wc_InitRsaKey(&ctx->public_key.key, NULL);
        if (result == 0)
        {
            result = wc_RsaPublicKeyDecode(in, &idx, &ctx->public_key.key, in_len);
            if ((result == 0) && (idx == in_len))
            {
                result = wc_InitRng(&ctx->public_key.rng);
                if (result == 0)
                {
                    result = wc_RsaSetRNG(&ctx->public_key.key, &ctx->public_key.rng);
                }
            }
        }

        if (result != 0)
        {
            status = CRYPTO_err;
        }
    }

    if (ctx != NULL)
    {
        if (status == CRYPTO_ok)
        {
            ctx->public_key.status = CRYPTO_ok;
        }
        else
        {
            ctx->public_key.status = CRYPTO_err;
            ctx->status = CRYPTO_err;
        }
    }

    return status;
}

crypto_status_t set_rsa_private_key(const uint8_t *in, uint32_t in_len, crypto_ctx_t *ctx)
{
    crypto_status_t status = CRYPTO_ok;
    uint32_t idx = 0u;
    int32_t result = 0;

    if ((ctx == NULL) || (ctx->status != CRYPTO_ok))
    {
        status = CRYPTO_err;
    }

    if ((status == CRYPTO_ok) &&
        ((in == NULL) || (in_len > (uint32_t)RSA_MAX_PRV_DER_KEY_BYTES)))
    {
        status = CRYPTO_err;
    }

    if (status == CRYPTO_ok)
    {
        if (ctx->private_key.status == CRYPTO_ok)
        {
            (void)wc_FreeRsaKey(&ctx->private_key.key);
            (void)wc_FreeRng(&ctx->private_key.rng);
        }

        (void)memset(&ctx->private_key, 0, sizeof(rsa_key_t));
        ctx->private_key.key = (RsaKey){0};
        ctx->private_key.status = CRYPTO_null;

        result = wc_InitRsaKey(&ctx->private_key.key, NULL);
        if (result == 0)
        {
            result = wc_RsaPrivateKeyDecode(in, &idx, &ctx->private_key.key, in_len);
            if ((result == 0) && (idx == in_len))
            {
                result = wc_InitRng(&ctx->private_key.rng);
                if (result == 0)
                {
                    result = wc_RsaSetRNG(&ctx->private_key.key, &ctx->private_key.rng);
                }
            }
        }

        if (result != 0)
        {
            status = CRYPTO_err;
        }
    }

    if (ctx != NULL)
    {
        if (status == CRYPTO_ok)
        {
            ctx->private_key.status = CRYPTO_ok;
        }
        else
        {
            ctx->private_key.status = CRYPTO_err;
            ctx->status = CRYPTO_err;
        }
    }

    return status;
}