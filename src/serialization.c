#include "types.h"
#include "internal_types.h"

crypto_status_t serialize(crypto_serialized_t *out, const crypto_ctx_t *ctx)
{
    crypto_status_t status = CRYPTO_ok;
    uint32_t offset = 0u;
    uint32_t data_len = 0u;
    uint32_t i = 0u;
    
    if (out == NULL)
    {
        status = CRYPTO_err;
    }
    
    if ((status == CRYPTO_ok) && ((ctx == NULL) || (ctx->status != CRYPTO_ok)))
    {
        status = CRYPTO_err;
    }
    
    if ((status == CRYPTO_ok) &&
        ((ctx->pkg.encrypted_msg.status != CRYPTO_ok) ||
         (ctx->pkg.encrypted_aes_key.status != CRYPTO_ok) ||
         (ctx->pkg.aes_iv.status != CRYPTO_used) ||
         (ctx->pkg.signature.status != CRYPTO_ok)))
    {
        status = CRYPTO_err;
    }
    
    if (status == CRYPTO_ok)
    {
        data_len = ctx->pkg.encrypted_msg.data_len;
        if (data_len > (uint32_t)AES_MAX_MESSAGE_BYTES)
        {
            status = CRYPTO_err;
        }
    }
    
    if (status == CRYPTO_ok)
    {
        (void)memset(out->data, 0, sizeof(out->data));
    
        out->data[0] = (uint8_t)(data_len >> 24u);
        out->data[1] = (uint8_t)(data_len >> 16u);
        out->data[2] = (uint8_t)(data_len >> 8u);
        out->data[3] = (uint8_t)(data_len);
    
        offset = sizeof(uint32_t);
    
        for (i = 0u; i < (uint32_t)AES_GCM_TAG_BYTES; i++)
        {
            out->data[offset] = ctx->pkg.encrypted_msg.tag[i];
            offset++;
        }
    
        for (i = 0u; i < (uint32_t)RSA_MODULUS_BYTES; i++)
        {
            out->data[offset] = ctx->pkg.encrypted_aes_key.data[i];
            offset++;
        }
    
        for (i = 0u; i < (uint32_t)AES_IV_BYTES; i++)
        {
            out->data[offset] = ctx->pkg.aes_iv.iv[i];
            offset++;
        }
    
        for (i = 0u; i < (uint32_t)RSA_MODULUS_BYTES; i++)
        {
            out->data[offset] = ctx->pkg.signature.data[i];
            offset++;
        }
    
        for (i = 0u; i < data_len; i++)
        {
            out->data[offset] = ctx->pkg.encrypted_msg.data[i];
            offset++;
        }

        out->data_len = offset;
    }
    
    if (out != NULL)
    {
        if (status == CRYPTO_ok)
        {
            out->status = CRYPTO_ok;
        }
        else
        {
            out->status = CRYPTO_err;
        }
    }
    
    return status;
}

crypto_status_t deserialize(const uint8_t *in, uint32_t in_size, crypto_ctx_t *ctx)
{
    crypto_status_t status = CRYPTO_ok;
    uint32_t offset = 0u;
    uint32_t data_len = 0u;
    uint32_t i = 0u;
    
    if ((ctx == NULL) || (ctx->status != CRYPTO_ok))
    {
        status = CRYPTO_err;
    }
    
    if ((status == CRYPTO_ok) &&
        ((in == NULL) ||
         (in_size <= (uint32_t)(SERIALIZED_DATA_SIZE - AES_MAX_MESSAGE_BYTES))))
    {
        status = CRYPTO_err;
    }
    
    if (status == CRYPTO_ok)
    {
        offset = 0u;
        data_len = (((uint32_t)in[0] << 24u) |
                    ((uint32_t)in[1] << 16u) |
                    ((uint32_t)in[2] << 8u)  |
                    ((uint32_t)in[3]));
        offset += sizeof(uint32_t);
    
        if (data_len > (uint32_t)AES_MAX_MESSAGE_BYTES)
        {
            status = CRYPTO_err;
        }
    }
    
    if (status == CRYPTO_ok)
    {
        ctx->pkg.encrypted_msg.data_len = data_len;
    
        for (i = 0u; i < (uint32_t)AES_GCM_TAG_BYTES; i++)
        {
            ctx->pkg.encrypted_msg.tag[i] = in[offset];
            offset++;
        }
    
        for (i = 0u; i < (uint32_t)RSA_MODULUS_BYTES; i++)
        {
            ctx->pkg.encrypted_aes_key.data[i] = in[offset];
            offset++;
        }
    
        for (i = 0u; i < (uint32_t)AES_IV_BYTES; i++)
        {
            ctx->pkg.aes_iv.iv[i] = in[offset];
            offset++;
        }
    
        for (i = 0u; i < (uint32_t)RSA_MODULUS_BYTES; i++)
        {
            ctx->pkg.signature.data[i] = in[offset];
            offset++;
        }
    
        for (i = 0u; i < data_len; i++)
        {
            ctx->pkg.encrypted_msg.data[i] = in[offset];
            offset++;
        }
    }
    
    if (ctx != NULL)
    {
        if (status == CRYPTO_ok)
        {
            ctx->pkg.encrypted_msg.status     = CRYPTO_ok;
            ctx->pkg.encrypted_aes_key.status = CRYPTO_ok;
            ctx->pkg.aes_iv.status            = CRYPTO_used;
            ctx->pkg.signature.status         = CRYPTO_ok;
            ctx->status                       = CRYPTO_ok;
        }
        else
        {
            ctx->pkg.encrypted_msg.status     = CRYPTO_err;
            ctx->pkg.encrypted_aes_key.status = CRYPTO_err;
            ctx->pkg.aes_iv.status            = CRYPTO_err;
            ctx->pkg.signature.status         = CRYPTO_err;
            ctx->status                       = CRYPTO_err;
        }
    }
    
    return status;
}