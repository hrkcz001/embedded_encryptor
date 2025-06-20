#include "../include/crypto.h"
#include "../include/internal_types.h"

crypto_status_t sign_message(crypto_ctx_t *ctx)
{
    crypto_status_t status = CRYPTO_ok;
    int32_t result;
    uint8_t hash[SHA256_SIGNATURE_BYTES] = { 0u };
    int32_t rsa_size;

    if ((ctx == NULL) || (ctx->status != CRYPTO_ok))
    {
        status = CRYPTO_err;
    }

    if ((status == CRYPTO_ok) &&
        ((ctx->private_key.status != CRYPTO_ok) ||
         (ctx->pkg.msg.status != CRYPTO_ok    ) ||
         (ctx->pkg.msg.data_len == 0U         ) ))
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
        result = wc_Sha256Hash(ctx->pkg.msg.data, ctx->pkg.msg.data_len, hash);
        if (result != 0)
        {
            status = CRYPTO_err;
        }
    }

    if (status == CRYPTO_ok)
    {
        (void)memset(&ctx->pkg.signature, 0, sizeof(rsa_encrypted_t));
        ctx->pkg.signature.status = CRYPTO_null;

        result = wc_RsaSSL_Sign(
            hash, sizeof(hash),
            ctx->pkg.signature.data, sizeof(ctx->pkg.signature.data),
            &ctx->private_key.key,
            &ctx->rng
        );

        if (result != (int32_t)RSA_MODULUS_BYTES)
        {
            status = CRYPTO_err;
        }
    }

    if (status == CRYPTO_ok)
    {
        ctx->pkg.signature.status = CRYPTO_ok;
    }
    else
    {
        if (ctx != NULL)
        {
            ctx->pkg.signature.status = CRYPTO_err;
            ctx->status = CRYPTO_err;
        }
    }

    return status;
}

crypto_status_t verify_signature(crypto_ctx_t *ctx)
{
    crypto_status_t status = CRYPTO_ok;
    int32_t result;
    int32_t rsa_size;
    uint8_t hash[SHA256_SIGNATURE_BYTES] = { 0u };
    uint8_t out[SHA256_SIGNATURE_BYTES] = { 0u };
    uint16_t i;

    if ((ctx == NULL) ||
        (ctx->status != CRYPTO_ok) ||
        (ctx->pkg.signature.status != CRYPTO_ok))
    {
        status = CRYPTO_err;
    }

    if ((status == CRYPTO_ok) &&
        ((ctx->public_key.status != CRYPTO_ok) ||
         (ctx->pkg.msg.status != CRYPTO_ok   ) ||
         (ctx->pkg.msg.data_len == 0u        ) ))
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
        result = wc_Sha256Hash(ctx->pkg.msg.data, ctx->pkg.msg.data_len, hash);
        if (result != 0)
        {
            status = CRYPTO_err;
        }
    }

    if (status == CRYPTO_ok)
    {
        result = wc_RsaSSL_Verify(
            ctx->pkg.signature.data, sizeof(ctx->pkg.signature.data),
            out, sizeof(out),
            &ctx->public_key.key
        );

        if (result != (int32_t)SHA256_SIGNATURE_BYTES)
        {
            status = CRYPTO_err;
        }
    }

    if (status == CRYPTO_ok)
    {
        for (i = 0u; i < SHA256_SIGNATURE_BYTES; ++i)
        {
            if (hash[i] != out[i])
            {
                status = CRYPTO_err;
                break;
            }
        }
    }

    if ((ctx != NULL) && (status != CRYPTO_ok))
    {
        ctx->status = CRYPTO_err;
    }

    return status;
}