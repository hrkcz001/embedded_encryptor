#ifndef CRYPTO_TYPES_H
#define CRYPTO_TYPES_H

#include "../wolfssl-5.8.0/include/wolfssl/options.h"
#include "../wolfssl-5.8.0/include/wolfssl/wolfcrypt/settings.h"
#include "../wolfssl-5.8.0/include/wolfssl/wolfcrypt/random.h"
#include "../wolfssl-5.8.0/include/wolfssl/wolfcrypt/hash.h"
#include "../wolfssl-5.8.0/include/wolfssl/wolfcrypt/rsa.h"
#include "../wolfssl-5.8.0/include/wolfssl/openssl/pem.h"

#include <stdint.h>
#include <stdbool.h>

typedef uint8_t                     crypto_status_t;
#define CRYPTO_ok                 ((crypto_status_t)( 1u))
#define CRYPTO_err                ((crypto_status_t)( 2u))
#define CRYPTO_used               ((crypto_status_t)( 3u))
#define CRYPTO_null               ((crypto_status_t)( 0u))

#define CRYPTO_INIT_err           ((crypto_status_t)(10u))
#define CRYPTO_SET_MSG_err        ((crypto_status_t)(11u))
#define CRYPTO_SET_PUB_KEY_err    ((crypto_status_t)(12u))
#define CRYPTO_SET_PRV_KEY_err    ((crypto_status_t)(13u))
#define CRYPTO_GEN_AES_KEY_err    ((crypto_status_t)(14u))
#define CRYPTO_GEN_AES_IV_err     ((crypto_status_t)(15u))
#define CRYPTO_AES_ENCRYPT_err    ((crypto_status_t)(16u))
#define CRYPTO_AES_DECRYPT_err    ((crypto_status_t)(17u))
#define CRYPTO_RSA_ENCRYPT_err    ((crypto_status_t)(18u))
#define CRYPTO_RSA_DECRYPT_err    ((crypto_status_t)(19u))
#define CRYPTO_SIGN_MSG_err       ((crypto_status_t)(20u))
#define CRYPTO_VERIFY_MSG_err     ((crypto_status_t)(21u))
#define CRYPTO_SERIALIZE_err      ((crypto_status_t)(22u))
#define CRYPTO_DESERIALIZE_err    ((crypto_status_t)(23u))

#define RSA_MODULUS_BYTES         ((uint16_t)(256u))
#define RSA_MAX_PUB_DER_KEY_BYTES ((uint16_t)(512u))
#define RSA_MAX_PRV_DER_KEY_BYTES ((uint16_t)(2048u))

#define SHA256_SIGNATURE_BYTES    ((uint16_t)( 32u))

#define AES_KEY_BYTES             ((uint8_t )( 32u))
#define AES_OK_OFFSET_BYTES       ((uint8_t )(  1u))
#define AES_IV_BYTES              ((uint8_t )( 16u))
#define AES_GCM_TAG_BYTES         ((uint8_t )( 16u))
#define AES_BLOCK_BYTES           ((uint8_t )( 16u))
#define AES_MAX_MESSAGE_BYTES     ((uint32_t)( 16u * AES_BLOCK_SIZE))

#define SERIALIZED_DATA_SIZE      ((uint32_t)(sizeof(uint32_t)            +   /*message length*/            \
                                              (uint32_t)AES_GCM_TAG_BYTES +   /*message tag*/               \
                                              (uint32_t)RSA_MODULUS_BYTES +   /*encrypted aes key*/         \
                                              (uint32_t)AES_IV_BYTES      +   /*aes initialization vector*/ \
                                              (uint32_t)RSA_MODULUS_BYTES +   /*encrypted signature*/       \
                                              (uint32_t)AES_MAX_MESSAGE_BYTES /*encrypted message*/        ))

struct CRYPTO_RSA_ENCRYPTED
{   uint8_t data[RSA_MODULUS_BYTES];
    crypto_status_t status;
};

struct CRYPTO_AES_KEY
{   uint8_t key[AES_KEY_BYTES];
    crypto_status_t status;
};

struct CRYPTO_AES_IV
{   uint8_t iv[AES_IV_BYTES];
    crypto_status_t status;
};

struct CRYPTO_RSA_KEY
{   RsaKey key;
    RNG rng;
    crypto_status_t status;
};

typedef struct CRYPTO_PLAIN_MESSAGE
{   uint8_t data[AES_MAX_MESSAGE_BYTES];
    uint32_t data_len;
    crypto_status_t status;
} crypto_plain_message_t;

struct CRYPTO_ENCRYPTED_MESSAGE
{   uint8_t data[AES_MAX_MESSAGE_BYTES];
    uint8_t tag[AES_GCM_TAG_BYTES];
    uint32_t data_len;
    crypto_status_t status;
};

struct CRYPTO_ENCRYPTED_PACKAGE{
    struct CRYPTO_PLAIN_MESSAGE msg;
    struct CRYPTO_ENCRYPTED_MESSAGE encrypted_msg;
    struct CRYPTO_RSA_ENCRYPTED signature;
    struct CRYPTO_RSA_ENCRYPTED encrypted_aes_key;
    struct CRYPTO_AES_KEY aes_key;
    struct CRYPTO_AES_IV aes_iv;
};

typedef struct CRYPTO_CTX{
    struct CRYPTO_ENCRYPTED_PACKAGE pkg;
    RNG rng;
    struct CRYPTO_RSA_KEY public_key;
    struct CRYPTO_RSA_KEY private_key;
    crypto_status_t status;
} crypto_ctx_t;

typedef struct CRYPTO_SERIALIZED{
    uint8_t data[SERIALIZED_DATA_SIZE];
    uint32_t data_len;
    crypto_status_t status;
} crypto_serialized_t;

#endif /* CRYPTO_TYPES_H */
