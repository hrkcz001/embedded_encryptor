#include "../include/crypto.h"

#include "private_first_rsa_key.h"
#include "public_first_rsa_key.h"
#include "private_second_rsa_key.h"
#include "public_second_rsa_key.h"

int main() {

    uint8_t example_msg[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };

    printf("Example message: \n");
    for(uint32_t i = 0; i < sizeof(example_msg); i++)
    {
        printf("%02X ", example_msg[i]);
    }
    printf("\n\n");
    
    crypto_ctx_t ctx1 = (crypto_ctx_t){0};
    crypto_ctx_t ctx2 = (crypto_ctx_t){0};

    crypto_status_t status = CRYPTO_null;
    crypto_serialized_t serialized = (crypto_serialized_t){0};
    crypto_plain_message_t plain_msg = (crypto_plain_message_t){0};

    status = encrypt_message(
        example_msg, sizeof(example_msg),
        &serialized,
        public_first_rsa_key, public_first_rsa_key_len,
        private_second_rsa_key, private_second_rsa_key_len,
        &ctx1
    );

    if (status != CRYPTO_ok)
    {
        printf("Encryption with first key failed: %d\n", status);
        free_crypto_context(&ctx1);
    }
    else
    {
        printf("Serialized data: \n");
        for(uint32_t i = 0; i < (uint32_t)(serialized.data_len); i++)
        {
            printf("%02X ", serialized.data[i]);
        }
        printf("\n\n");

        status = decrypt_message(
            serialized.data, serialized.data_len,
            &plain_msg,
            public_second_rsa_key, public_second_rsa_key_len,
            private_first_rsa_key, private_first_rsa_key_len,
            &ctx2
        );
        if (status != CRYPTO_ok)
        {
            printf("Decryption with second key failed: %d\n", status);
            free_crypto_context(&ctx2);
        }
        else
        {
            printf("Decrypted message: \n");
            for(uint32_t i = 0; i < plain_msg.data_len; i++)
            {
                printf("%02X ", plain_msg.data[i]);
            }
            printf("\n\n");

            (void)memset(serialized.data, 0, sizeof(serialized.data));
            (void)memset(plain_msg.data, 0, sizeof(plain_msg.data));
        }
    }

    return status;
}