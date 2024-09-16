#include <stdlib.h>
#include <string.h>

#include "geotab_crypto.h"
#include "geotab_crypto_errors.h"

int crypt_buffer(struct crypt_context* context, uint8_t* output,
                 const uint8_t* input, unsigned length) {
  if (!context || !input || !output || context->lengthKey == 0) {
      return GEOTAB_CRYPTO_ERROR_INVALID_ARGS;
  }
  
  uint8_t* k = context->key;
  unsigned* i = &context->index;
  for (unsigned elem = 0; elem < length; ++elem) {
    k[*i] = (k[*i] + *i) & 255;  // k[i] = (k[i] + i) mod 256. The optimization is
                              // possible because k is unsigned
    output[elem] = input[elem] ^ k[*i];
    *i = (*i + 1) % context->lengthKey;
  }

  return GEOTAB_CRYPTO_SUCCESS;
}

const char* crypt_get_library_version() { return GEOTAB_CRYPTO_VERSION; }
