#ifndef GEOTAB_CRYPTO_H
#define GEOTAB_CRYPTO_H

#ifdef __cplusplus
extern "C" {
#endif
#include <stdint.h>

#define GEOTAB_CRYPTO_VERSION "v1.0.0"

/**
 * @struct crypt_context
 * @brief Holds required cryptographic information for decrypt/encrypt operations
 *
 * Holds the cryptographic key, its length, and the current index used for the
 * cryptographic operations
 */
struct crypt_context {
    uint8_t* key;
    unsigned lengthKey;
    unsigned index;
};

/**
 * @brief Encrypts or decrypts a buffer using the specified cryptographic context.
 *
 * This function processes the input buffer and produces an output buffer of the same length,
 * using the cryptographic context provided. It implements a symmetric encryption algorithm
 * so the decrypt/encrypt operation depends on the provided input state.
 *
 * @param context Pointer to the cryptographic context to be used for the operation.
 * @param output Pointer to the buffer where the encrypted/decrypted message will be stored.
 *               Must be at least 'length' bytes long.
 * @param input Pointer to the buffer containing the message to be encrypted/decrypted.
 *              Must be at least 'length' bytes long.
 * @param length The length of the message to decrypt.
 *              Must be greater than 0.
 *
 * @return Result of the operation. GEOTAB_CRYPTO_SUCCESS if success. GEOTAB_CRYPTO_ERROR_INVALID_ARGS if any of the arguments is invalid.
 */
int crypt_buffer(struct crypt_context *context, uint8_t *output, const uint8_t *input, unsigned length);

/**
 * @brief Return the current version of the geotab_crypto library.
 *
 * @return String with the current version
 */
const char* crypt_get_library_version();

#ifdef __cplusplus
}
#endif


#endif // GEOTAB_CRYPTO_H