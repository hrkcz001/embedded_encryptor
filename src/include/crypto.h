#ifndef ZEL40_CRYPTO_H
#define ZEL40_CRYPTO_H

#include "types.h"

/* * Initialize the crypto context(ctx).
 *   Returns CRYPTO_ok on success, or CRYPTO_err if the context is NULL or initialization fails.
 */
crypto_status_t init_crypto_context(crypto_ctx_t *ctx);

/* * Free the crypto context(ctx).
 *   Cleans up the resources used by the crypto context and sets the context status to CRYPTO_used.
 *   Returns CRYPTO_ok on success, or CRYPTO_err if the context is NULL.
 */
crypto_status_t free_crypto_context(crypto_ctx_t *ctx);

/* * Serialize all necessary data from the crypto context(ctx) into a provided crypto_serialized_t structure(out). 
 *   It's expected that structure has uint8_t array of size SERIALIZED_DATA_SIZE and a status field.
 *   Returns CRYPTO_ok on success, or CRYPTO_err if the context is NULL or serialization fails.
 */
crypto_status_t serialize  (crypto_serialized_t *out, const crypto_ctx_t *ctx);

/* * Deserialize data from a uint8_t array(in) into the crypto context(ctx).
 *   The input data should be in the format produced by the serialize function.
 *   The function will extract the message length, tag, encrypted AES key, AES IV, signature, and encrypted message from the input data for later decryption.
 *   Expects a pointer to the input data(in), its size(in_size), and a pointer to the crypto context(ctx).
 *   Returns CRYPTO_ok on success, or CRYPTO_err if the input data is invalid or the context is NULL or its status is not CRYPTO_ok.
 */
crypto_status_t deserialize(const uint8_t *in, uint32_t in_size, crypto_ctx_t *ctx);

/* * Sets plain message to be encrypted.
 *   The message is stored in the crypto context(ctx) and can be used later for encryption.
 *   Expects a pointer to the crypto context(ctx), a pointer to the input data(in), and the length of the input data(in_len).
 *   Returns CRYPTO_ok on success, or CRYPTO_err if the input data is invalid.
 */
crypto_status_t set_message(crypto_ctx_t *ctx, const uint8_t *in, uint32_t in_len);

/* * Generate AES key with default ok_bits.
 *   Sets first byte of the AES key to ok_bits.
 *   Other bytes are randomly generated.
 *   The key is stored in the crypto context(ctx) and can be used later for encryption.
 *   Returns CRYPTO_ok on success, or CRYPTO_err if the context is invalid or key generation fails.
 */
crypto_status_t generate_aes_key       (uint8_t ok_bits, crypto_ctx_t *ctx);

/* * Generate random AES key.
 *   The key is stored in the crypto context(ctx) and can be used later for encryption
 *   Returns CRYPTO_ok on success, or CRYPTO_err if the context is invalid or key generation fails.
 */
crypto_status_t generate_random_aes_key(crypto_ctx_t *ctx);

/* * Generate AES IV (Initialization Vector).
 *   The IV is stored in the crypto context(ctx) and can be used later for encryption.
 *   Returns CRYPTO_ok on success, or CRYPTO_err if the context is invalid or IV generation fails.
 */
crypto_status_t generate_aes_iv        (crypto_ctx_t *ctx);

/* * Encrypt the message in the crypto context(ctx) using AES GCM.
 *   Uses the AES key and IV stored in the context.
 *   The encrypted message and tag are stored in the context.
 *   Returns CRYPTO_ok on success, or CRYPTO_err if the context is invalid or encryption fails.
 */
crypto_status_t aes_encrypt(crypto_ctx_t *ctx);

/* * Decrypt the encrypted message in the crypto context(ctx) using AES GCM.
 *   Uses the AES key, IV and tag stored in the context.
 *   The decrypted message is stored in the context.
 *   Returns CRYPTO_ok on success, or CRYPTO_err if the context is invalid or decryption fails.
 */
crypto_status_t aes_decrypt(crypto_ctx_t *ctx);

/* * RSA encryption of AES key.
 *   Encrypts the AES key using RSA public key stored in the context.
 *   The encrypted AES key is stored in the context.
 *   Returns CRYPTO_ok on success, or CRYPTO_err if the context is invalid or encryption fails.
 */ 
crypto_status_t rsa_encrypt_aes_key(crypto_ctx_t *ctx);

/* * RSA decryption of AES key.
 *   Decrypts the AES key using RSA private key stored in the context.
 *   The decrypted AES key is stored in the context.
 *   Returns CRYPTO_ok on success, or CRYPTO_err if the context is invalid or decryption fails.
 */
crypto_status_t rsa_decrypt_aes_key(crypto_ctx_t *ctx);

/* * Set RSA public key.
 *   Expects a pointer to the input data(in) containing the public key and its length(in_len).
 *   It's expected that the key is in DER format and its length is less than RSA_MAX_PUB_DER_KEY_BYTES.
 *   The public key is stored in the crypto context(ctx).
 *   Returns CRYPTO_ok on success, or CRYPTO_err if the input data or context is invalid.
 */
crypto_status_t set_rsa_public_key (const uint8_t *in, uint32_t in_len, crypto_ctx_t *ctx);

/* * Set RSA private key.
 *   Expects a pointer to the input data(in) containing the private key and its length(in_len).
 *   It's expected that the key is in DER format and its length is less than RSA_MAX_PRV_DER_KEY_BYTES.
 *   The private key is stored in the crypto context(ctx).
 *   Returns CRYPTO_ok on success, or CRYPTO_err if the input data or context is invalid.
 */
crypto_status_t set_rsa_private_key(const uint8_t *in, uint32_t in_len, crypto_ctx_t *ctx);

/* * Sign message using RSA private key.
 *   Signs the message in the crypto context(ctx) using RSA private key and message stored in the context.
 *   The signature is stored in the context.
 *   Returns CRYPTO_ok on success, or CRYPTO_err if the context is invalid or signing fails.
 */
crypto_status_t sign_message    (crypto_ctx_t *ctx);

/* * Verify signature using RSA public key.
 *   Verifies the signature stored in the crypto context(ctx) matches the message stored in the context.
 *   Returns CRYPTO_ok if the signature is valid, or CRYPTO_err if the context is invalid or verification fails.
 */
crypto_status_t verify_signature(crypto_ctx_t *ctx);

/* * Encrypt a message.
 *   Expects a pointer to an input data(in) containing a message to be encrypted and its size(in_size).
 *   Expects a pointer to a crypto_serialized_t structure(out) where a encrypted message will be stored.
 *   Expects a pointer to a RSA public key(public_key) and its length(public_key_len).
 *   Expects a pointer to a RSA private key(private_key) and its length(private_key_len).
 *   Expects a pointer to uninitialized crypto_ctx_t structure(ctx).
 *   The function will encrypt the message using AES GCM, encrypt the AES key using RSA, and sign the message using RSA.
 *   Size of the input data should not exceed AES_MAX_MESSAGE_BYTES.
 *   RSA keys should be in DER format and their lengths should not exceed RSA_MAX_PUB_DER_KEY_BYTES and RSA_MAX_PRV_DER_KEY_BYTES respectively.
 *   Returns CRYPTO_ok on success, or error which indicates a type of failure, possible errors are defined in types.h
 *   Frees the crypto context(ctx) after encryption if successful, otherwise it can be used for udentifying an error, and should be freed later.
 */
crypto_status_t encrypt_message( const uint8_t *in
                               ,       uint32_t in_size
                               ,       crypto_serialized_t *out
                               , const uint8_t *public_key
                               ,       uint32_t public_key_len
                               , const uint8_t *private_key
                               ,       uint32_t private_key_len
                               ,       crypto_ctx_t *ctx);
/* * Decrypt a message.
 *   Expects a pointer to a input data(in) containing a serialized encrypted message and its size(in_size).
 *   Expects a pointer to a crypto_plain_message_t structure(out) where a decrypted message will be stored.
 *   Expects a pointer to uninitialized crypto_ctx_t structure(ctx).
 *   Expects a pointer to an RSA public key(public_key) and its length(public_key_len).
 *   Expects a pointer to an RSA private key(private_key) and its length(private_key_len).
 *   The input data should be in the format produced by the encrypt_message function.
 *   RSA keys should be in DER format and their lengths should not exceed RSA_MAX_PUB_DER_KEY_BYTES and RSA_MAX_PRV_DER_KEY_BYTES respectively.
 *   The function will deserialize the input data, decrypt the AES key using RSA, decrypt the message using AES GCM, and verify the signature.
 *   Returns CRYPTO_ok on success, or error which indicates a type of failure, possible errors are defined in types.h
 *   Frees the crypto context(ctx) after decryption if successful, otherwise it can be used for identifying an error, and should be freed later.
 */
crypto_status_t decrypt_message( const uint8_t *in
                               ,       uint32_t in_size
                               ,       crypto_plain_message_t *out
                               , const uint8_t *public_key
                               ,       uint32_t public_key_len
                               , const uint8_t *private_key
                               ,       uint32_t private_key_len
                               ,       crypto_ctx_t *ctx);

#endif /* ZEL40_CRYPTO_H */