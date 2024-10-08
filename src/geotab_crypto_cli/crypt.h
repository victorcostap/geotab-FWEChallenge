#ifndef CRYPT_H
#define CRYPT_H

#include <stdio.h>
#include <geotab_crypto.h>


/**
 * @brief Prints the usage information for the program.
 *
 * @param progName The name of the program, typically argv[0].
 */
void printUsage(const char *progName);

/**
 * @brief Cleans up resources by closing file pointers and freeing allocated memory.
 *
 * @param in Pointer to the input file to be closed.
 * @param out Pointer to the output file to be closed.
 * @param key Pointer to the allocated memory with the key to be freed.
 */
void cleanUpResources(FILE *in, FILE *out, uint8_t *key);

/**
 * @brief Retrieves the key length from the provided key file and updates the context.
 *
 *
 * @param kf Pointer to the file with the stored key
 * @param context Pointer to the cryptographic context
 */
void getKeyLength(FILE *kf, struct crypt_context *context);

/**
 * @brief Reads the cryptographic key from a specified file.
 *
 * @param keyFile String with the path of the file with the key
 * @param context Cryptographic context where to store the key and its length
 */
void readKeyFromFile(const char *keyFile,
                    struct crypt_context *context);

/**
 * @brief Processes the input from the input stream and writes the result to the given output stream.
 * 
 * The operation is done character by character to allow processing the input as it arrives
 *
 * @param in Pointer to the input stream.
 * @param out Pointer to the output stream.
 * @param context Pointer to the cryptographic context with the key and other required information
 */
void processInput(FILE *in, FILE *out, struct crypt_context *context);

#endif // CRYPT_H
