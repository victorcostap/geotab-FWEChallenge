#ifndef CRYPT_H
#define CRYPT_H

#include <stdio.h>
#include <geotab_crypto.h>


void printUsage(const char *progName);

void cleanUpResources(FILE *in, FILE *out, uint8_t *key);

void getKeyLength(FILE *kf, struct crypt_context *context);

void readKeyFromFile(const char *keyFile,
                            struct crypt_context *context);

void processInput(FILE *in, FILE *out, struct crypt_context *context,
                  uint8_t *key);

#endif // CRYPT_H
