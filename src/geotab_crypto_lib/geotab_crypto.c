#include "geotab_crypto.h"

int crypt_buffer(struct crypt_context* context, uint8_t* output, const uint8_t* input,
                 unsigned length) {
  return 0;
}

const char* crypto_get_library_version() { return GEOTAB_CRYPTO_VERSION; }
