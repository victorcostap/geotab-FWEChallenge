#ifndef GEOTAB_CRYPTO_H
#define GEOTAB_CRYPTO_H

#ifdef __cplusplus
extern "C" {
#endif
#include <stdint.h>

#define GEOTAB_CRYPTO_VERSION "v1.0.0"

struct crypt_context {
    
};

int crypt_buffer(struct crypt_context *context, uint8_t *output, const uint8_t *input, unsigned length);

const char* crypto_get_library_version();

#ifdef __cplusplus
}
#endif


#endif // GEOTAB_CRYPTO_H